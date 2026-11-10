FROM python:3.12-slim
WORKDIR /app
COPY app.py .
ENV PORT=8003
EXPOSE 8003
USER 65534
CMD ["python", "app.py"]
