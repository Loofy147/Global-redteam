# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements files into the container
COPY requirements.txt .
COPY redsight_mvp/api/requirements.txt ./redsight_mvp/api/requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r redsight_mvp/api/requirements.txt

# Copy the rest of the application's code into the container
COPY . .

# Set the entrypoint to run the orchestrator
ENTRYPOINT ["python3", "-m", "src.global_red_team.red_team_orchestrator"]
