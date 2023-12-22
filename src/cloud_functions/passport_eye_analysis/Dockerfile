# Below Docker file code for GCP Cloud Run
# Details: https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service

# Use the official lightweight Python image
FROM python:3.10.10-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Copy local code to the container image
ENV APP_HOME /app
COPY . $APP_HOME
WORKDIR $APP_HOME

# For the OCR to work
RUN apt update
RUN apt install -y tesseract-ocr libtesseract-dev

# Install the dependencies using the copied python script with integrity checks
RUN pip install -r requirements.txt
RUN pip install -U "uvicorn[standard]" gunicorn

# Remove the python script and the requirements file
# after the dependencies are installed
RUN rm -f requirements.txt

# Set PORT env for flask app to Listen on port 8080
ENV PORT 8080

# Run the web service on container startup. Here we use the gunicorn webserver.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling
CMD exec gunicorn --bind :$PORT --workers 4 --worker-class uvicorn.workers.UvicornWorker --timeout 0 main:app