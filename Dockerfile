# Stage 1: Build the application
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN pip install --upgrade pip

# Copy and install Python dependencies
COPY requirements.txt .
COPY redsight_mvp/api/requirements.txt ./redsight_mvp/api/requirements.txt
RUN pip install --no-cache-dir --user -r requirements.txt
RUN pip install --no-cache-dir --user -r redsight_mvp/api/requirements.txt

# Copy the application code
COPY . .

# Stage 2: Create the final production image
FROM python:3.12-slim

# Create a non-root user
RUN useradd --create-home appuser
WORKDIR /home/appuser/app
USER appuser

# Copy installed dependencies and application code from the builder stage
COPY --from=builder /root/.local /home/appuser/.local
COPY --from=builder /app .

# Set the PATH to include the installed packages
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Expose the port for the vulnerable app (if needed)
EXPOSE 5000
