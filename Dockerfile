# Χρησιμοποιούμε την επίσημη ελαφριά εικόνα Python
FROM python:3.11-slim

# Ορίζουμε τον φάκελο εργασίας μέσα στο container
WORKDIR /app

# Εγκαθιστούμε το Streamlit (απαραίτητο για το Web GUI)
RUN pip install --no-cache-dir streamlit

# Αντιγράφουμε τον κώδικα της εφαρμογής μας
COPY app.py .

# Δημιουργούμε το mount point για τα αρχεία του συστήματος
RUN mkdir /data_to_monitor

# Ενημερώνουμε το Docker ότι η εφαρμογή τρέχει στην πόρτα 8501
EXPOSE 8501

# Εντολή για την εκκίνηση του Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
