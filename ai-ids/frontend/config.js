// The one setting you need to change after deploying the backend.
//
// LOCAL DEV: leave as-is, it auto-detects localhost.
// DEPLOYED:  replace with your Render backend URL, e.g.
//            window.API_BASE_URL = "https://ai-ids-backend.onrender.com";

window.API_BASE_URL =
  (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" || window.location.hostname === "")
    ? "http://localhost:8000"
    : "https://REPLACE-WITH-YOUR-BACKEND-URL.onrender.com";
