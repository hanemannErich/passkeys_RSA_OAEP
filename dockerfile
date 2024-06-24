FROM python:3.10.14-slim

# Install dependencies
COPY . .

RUN pip install -r requirements.txt

# Run the application
CMD ["bash"]