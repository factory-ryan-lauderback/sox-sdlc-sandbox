FROM python:3.12-slim
WORKDIR /app
COPY app.py .
ENV PORT=8002
EXPOSE 8002
USER 65534
CMD ["python", "app.py"]
