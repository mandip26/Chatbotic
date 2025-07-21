from fastapi import FastAPI
import uvicorn
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Chatbotic API service", description="API for Chatbotic services")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Welcome to the Chatbotic API service"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
    )