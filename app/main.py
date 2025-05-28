from fastapi import FastAPI
from app.routes.predict_phishing_route import router

app = FastAPI()
app.include_router(router)

#run project : ivivorn main:app --reload