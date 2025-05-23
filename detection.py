import cv2
import torch
import numpy as np
import os
from datetime import datetime
from collections import defaultdict
import math
from datetime import datetime

from models.experimental import attempt_load
from utils.datasets import LoadStreams
from utils.general import scale_coords, non_max_suppression, check_img_size
from utils.plots import plot_one_box
from utils.torch_utils import select_device
from database import db, Intrusion
from flask import current_app

# Tracker class
class CentroidTracker:
    def __init__(self, max_disappeared=30, max_distance=50):
        self.next_object_id = 0
        self.objects = dict()
        self.disappeared = dict()
        self.saved_screenshots = set()
        self.max_disappeared = max_disappeared
        self.max_distance = max_distance

    def register(self, centroid):
        self.objects[self.next_object_id] = centroid
        self.disappeared[self.next_object_id] = 0
        self.next_object_id += 1

    def deregister(self, object_id):
        del self.objects[object_id]
        del self.disappeared[object_id]
        self.saved_screenshots.discard(object_id)

    def update(self, input_centroids):
        # If there are no centroids, mark existing ones as disappeared
        if len(input_centroids) == 0:
            for object_id in list(self.disappeared.keys()):
                self.disappeared[object_id] += 1
                if self.disappeared[object_id] > self.max_disappeared:
                    self.deregister(object_id)
            return self.objects

        if len(self.objects) == 0:
            for centroid in input_centroids:
                self.register(centroid)
            return self.objects

        object_ids = list(self.objects.keys())
        object_centroids = list(self.objects.values())

        if len(object_centroids) == 0 or len(input_centroids) == 0:
            return self.objects

        distances = np.linalg.norm(np.array(object_centroids)[:, None] - np.array(input_centroids), axis=2)
        rows = distances.min(axis=1).argsort()
        cols = distances.argmin(axis=1)[rows]

        used_rows = set()
        used_cols = set()

        for row, col in zip(rows, cols):
            if row in used_rows or col in used_cols:
                continue
            if distances[row, col] > self.max_distance:
                continue

            object_id = object_ids[row]
            self.objects[object_id] = input_centroids[col]
            self.disappeared[object_id] = 0
            used_rows.add(row)
            used_cols.add(col)

        unused_rows = set(range(len(object_centroids))) - used_rows
        for row in unused_rows:
            object_id = object_ids[row]
            self.disappeared[object_id] += 1
            if self.disappeared[object_id] > self.max_disappeared:
                self.deregister(object_id)

        unused_cols = set(range(len(input_centroids))) - used_cols
        for col in unused_cols:
            self.register(input_centroids[col])

        return self.objects


# Load YOLOv7 model
device = select_device('')
model = attempt_load('best.pt', map_location=device)
stride = int(model.stride.max())
imgsz = check_img_size(640, s=stride)
names = model.module.names if hasattr(model, 'module') else model.names
colors = [[np.random.randint(0, 255) for _ in range(3)] for _ in names]

# Create folder for intrusion screenshots
class_names = ['Bus', 'Car', 'Jeep', 'Motorcycle', 'Truck']
screenshot_dir = "intrusion_screenshots"
os.makedirs(screenshot_dir, exist_ok=True)

for name in class_names:
    intrusion_path = os.path.join(screenshot_dir, f"{name}_intrusions")
    os.makedirs(intrusion_path, exist_ok=True)

# Initialize tracker
tracker = CentroidTracker()

# Video source setup
def generate_frames(video_source=0):
    from app import app
    dataset = LoadStreams(str(video_source), img_size=imgsz, stride=stride)

    for path, img, im0s, _ in dataset:
        img = torch.from_numpy(img).to(device)
        img = img.float() / 255.0
        if img.ndimension() == 3:
            img = img.unsqueeze(0)

        # Inference
        with torch.no_grad():
            pred = model(img)[0]
        pred = non_max_suppression(pred, 0.65, 0.45, classes=None)

        bike_lane_boxes = []
        vehicle_boxes = []
        vehicle_names = []

        for det in pred:
            im0 = im0s[0].copy()
            if len(det):
                det[:, :4] = scale_coords(img.shape[2:], det[:, :4], im0.shape).round()
                for *xyxy, conf, cls in det:
                    label = f'{names[int(cls)]} {conf:.2f}'
                    x1, y1, x2, y2 = map(int, xyxy)

                    if names[int(cls)] == "Bike-lane":
                        bike_lane_boxes.append((x1, y1, x2, y2))
                        plot_one_box(xyxy, im0, label=label, color=colors[int(cls)], line_thickness=1)
                    elif names[int(cls)] != "Bike":
                        vehicle_boxes.append((x1, y1, x2, y2))
                        vehicle_names.append(names[int(cls)])
                        # plot_one_box(xyxy, im0, label=label, color=colors[int(cls)], line_thickness=1)

        intrusion_centroids = []
        intrusion_boxes = []
        intrusion_labels = []

        for bl_x1, bl_y1, bl_x2, bl_y2 in bike_lane_boxes:
            for i, vehicle in enumerate(vehicle_boxes):
                v_x1, v_y1, v_x2, v_y2 = vehicle
                if (v_x1 < bl_x2) and (v_x2 > bl_x1) and (v_y1 < bl_y2) and (v_y2 > bl_y1):
                    cx = int((v_x1 + v_x2) / 2)
                    cy = int((v_y1 + v_y2) / 2)
                    intrusion_centroids.append((cx, cy))
                    intrusion_boxes.append(vehicle)
                    intrusion_labels.append(vehicle_names[i])

        objects = tracker.update(intrusion_centroids)

        for object_id, centroid in objects.items():
            for i, (cx, cy) in enumerate(intrusion_centroids):
                if math.hypot(cx - centroid[0], cy - centroid[1]) < 1:
                    v_x1, v_y1, v_x2, v_y2 = intrusion_boxes[i]
                    name = intrusion_labels[i]
                    plot_one_box((v_x1, v_y1, v_x2, v_y2), im0, label=f"Intrusion ID {object_id}", color=(0, 0, 255), line_thickness=1)

                    if object_id not in tracker.saved_screenshots:
                        tracker.saved_screenshots.add(object_id)

                        intrusion_region = im0[v_y1:v_y2, v_x1:v_x2]
                        intrusion_region_resized = cv2.resize(intrusion_region, (640, 640))

                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        screenshot_filename = f"intrusion_{object_id}_{timestamp}.jpg"
                        screenshot_path = os.path.join("intrusion_screenshots", f"{name}_intrusions", screenshot_filename)
                        cv2.imwrite(screenshot_path, intrusion_region_resized)
                        print(f"Intrusion detected! Screenshot saved: {screenshot_filename}")

                        with app.app_context():
                            new_intrusion = Intrusion(
                                timestamp=datetime.now(),
                                vehicle_type=name,
                                image_path=screenshot_path
                            )
                            db.session.add(new_intrusion)
                            db.session.commit()


        _, buffer = cv2.imencode('.jpg', im0)
        frame_bytes = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')