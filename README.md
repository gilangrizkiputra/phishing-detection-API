# Phishing Detection API

FastAPI-powered REST API to detect phishing websites based on URL features using a pre-trained CatBoost model. The system extracts 29 features from the input URL and classifies it as phishing or safe.

## 🔧 Features

- FastAPI backend
- CatBoost ML model
- Feature extraction from raw URL
- Probability scores
- JSON response format

---

## Libraries Used

| Library         | Fungsi                                                                 |
|----------------|------------------------------------------------------------------------|
| `fastapi`       | Framework utama API                                                    |
| `uvicorn`       | ASGI server untuk menjalankan FastAPI                                  |
| `joblib`        | Load model `.pkl` hasil training                                       |
| `numpy`         | Operasi array dan numerik                                              |
| `pandas`        | Load CSV dan manipulasi data                                           |
| `requests`      | Fetch konten HTML                                                      |
| `beautifulsoup4`| Parsing konten HTML                                                    |
| `python-whois`  | Mengambil data WHOIS dari domain                                       |
| `catboost`      | Library ML untuk model klasifikasi                                     |

---

## Getting Started

1. **Clone the Repository**
   ```terminal
   git clone https://github.com/your-username/phishing-detection-api.git
2. Create & Activate Virtual Environment
   ```
   python -m venv myenv
   myenv\Scripts\activate 
4. Install Dependencies
   ```
   pip install -r requirements.txt
   
6. Run the Server
   ```
   uvicorn app.main:app --reload

