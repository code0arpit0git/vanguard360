# Use a lightweight, official Python image
FROM python:3.11-slim

# Keep Python from generating .pyc files and enable live terminal output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your entire project into the container
COPY . .

# SECURITY BEST PRACTICE: Create a non-root user to run the application
RUN useradd -m vanguard_user && chown -R vanguard_user:vanguard_user /app
USER vanguard_user

# Expose the Streamlit port
EXPOSE 8501

# Command to launch the dashboard inside the container
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
