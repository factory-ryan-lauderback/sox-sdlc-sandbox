FROM python:3.12-slim
WORKDIR /app
COPY app.py .
ENV PORT=8001
EXPOSE 8001
USER 65534
CMD ["python", "app.py"]
