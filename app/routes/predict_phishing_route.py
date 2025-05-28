from fastapi import APIRouter
from app.models.predict_phishing_schema import URLInput
from app.services.predict_phishing_service import predict_url

router = APIRouter()

@router.post("/predict")
def predict_phishing(data: URLInput):
    return predict_url(data.url)
