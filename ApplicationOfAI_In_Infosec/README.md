# Applications of AI in InfoSec - HTB Academy

An interactive, hands-on repository covering the practical implementation of Machine Learning and Deep Learning models for cybersecurity defensive operations, based on the **Hack The Box (HTB) Academy** module.

---

## 📌 Module Overview

This module bridges the gap between theoretical AI concepts and real-world information security applications. It covers the end-to-end data science lifecycle—from raw data extraction to feature engineering, model training, and performance evaluation.

### Key Learning Objectives
* **Data Pipelines:** Process tabular logs, raw network packets, binary file byte arrays, and unstructured text.
* **Feature Engineering:** Master text tokenization, TF-IDF vectorization, normalization, and handling missing data.
* **Supervised Learning:** Build traditional ML classifiers (Naive Bayes, Random Forests) for tabular and textual alerts.
* **Deep Learning:** Leverage Computer Vision (PyTorch, ResNet) to classify structural anomalies in binary executables.
* **Model Validation:** Evaluate defensive models using Confusion Matrices, Precision, Recall, and F1-Scores.

---

## 🛠️ Environment & Prerequisites

To run the notebooks and scripts locally, configure the following environment:

* **Hardware Recommendation:** Minimum 4GB RAM, modern multi-core CPU (GPU optional for deep learning sections).
* **Environment Manager:** Miniconda / Anaconda Python 3.10+
* **Core Libraries:** `scikit-learn`, `pandas`, `numpy`, `torch`, `torchvision`, `matplotlib`, `jupyterlab`

### Quick Setup

```bash


# Create and activate environment
conda create -n ai-infosec python=3.10 -y
conda activate ai-infosec

# Install dependencies
pip install pandas numpy scikit-learn torch torchvision matplotlib jupyterlab
```

---

## 📂 Repository Structure & Built Models

The repository is broken down into four core sections representing the hands-on labs within the HTB module:

### 1. Phishing & Spam Classification (`01_spam_classifier/`)
* **Algorithm:** Multinomial Naive Bayes
* **Concept:** Parses raw text emails into numerical vectors using text tokenization and **TF-IDF (Term Frequency-Inverse Document Frequency)** vectorization.
* **Objective:** Automatically classify phishing vs. benign communication.

### 2. Network Anomaly Detection (`02_network_anomalies/`)
* **Algorithm:** Random Forest Classifier
* **Concept:** Processes structured firewall, NetFlow, and host logs (using the NSL-KDD reference dataset). Handles feature scaling and categorical encoding.
* **Objective:** Detect live network intrusions, beaconing behavior, and lateral movement.

### 3. Malware Image Classification (`03_malware_vision/`)
* **Algorithm:** PyTorch Deep Learning (ResNet50 / Custom CNN)
* **Concept:** Transforms raw binary `.exe` files into 2D byte arrays and renders them as grayscale or color images. Applies transfer learning on pretrained vision models.
* **Objective:** Identify and classify malware families based on structural execution patterns.

### 4. Skills Assessment: Sentiment Analysis (`04_skills_assessment/`)
* **Algorithm:** Optimized Vectorization + Classifier Pipeline
* **Concept:** The capstone challenge requiring an end-to-end pipeline to evaluate text sequences against an external, active HTB API endpoint.
* **Objective:** Successfully pass validation thresholds against live streaming testing data.

---

## 📊 Model Evaluation Matrix

Every built model documents performance using standard evaluation metrics:

* **Precision:** Minimizing False Positives (e.g., ensuring harmless system traffic isn't flagged as malicious).
* **Recall (Sensitivity):** Minimizing False Negatives (e.g., ensuring no critical malicious binaries slip through undetected).
* **F1-Score:** Harmonic mean balancing system accuracy.

---

## ⚠️ Disclaimer

This repository is for educational and research purposes only. All datasets, concepts, and methodologies originate from the Hack The Box Academy curriculum. Do not use these implementations on active corporate assets without prior authorization.
