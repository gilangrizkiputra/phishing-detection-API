import joblib
from pathlib import Path
import numpy as np
from app.utils.feature_extraction import FeatureExtraction
from app.utils.convert_models import convertion

model_path = Path(__file__).resolve().parent.parent / "assets" / "newmodel_cat_try5.pkl"
model = joblib.load(model_path)

feature_names = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", 
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon", 
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags", 
    "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding", "StatusBarCust", 
    "DisableRightClick", "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording", 
    "WebsiteTraffic", "GoogleIndex", "LinksPointingToPage", "StatsReport"
]

def predict_url(url: str):
    try:
        features = FeatureExtraction(url).get_features()

        if len(features) != len(feature_names):
            return {"error": f"Jumlah fitur tidak sesuai: {len(features)} dari seharusnya {len(feature_names)}"}

        x = np.array(features).reshape(1, -1)
        prediction = model.predict(x)[0]
        probabilities = model.predict_proba(x)[0].tolist()

        result = convertion(url, prediction)
        return {
            "url": result[0],
            "status": result[1],
            "prediction": int(prediction),
            "probability": {
                "phishing": probabilities[0],
                "non_phishing": probabilities[1]
            }
        }
    except Exception as e:
        return {"error": str(e)}


#run project : ivivorn main:app --reload