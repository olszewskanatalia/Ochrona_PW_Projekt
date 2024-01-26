# Use the Nginx image
FROM nginx

# Install ufw
RUN apt-get update && \
    apt-get install -y ufw && \
    rm -rf /var/lib/apt/lists/*

# Remove the default nginx.conf
RUN rm /etc/nginx/conf.d/default.conf

# Replace with our own nginx.conf
COPY nginx.conf /etc/nginx/conf.d/

# Add ssl certification
COPY ssl/nginx-selfsigned.crt /etc/ssl/certs/
COPY ssl/nginx-selfsigned.key /etc/ssl/private/
COPY ssl/dhparam.pem /etc/nginx/

# Add snippets
COPY snippets/* /etc/nginx/snippets/

# Configure ufw
RUN ufw allow 80/tcp && \
    ufw allow 443/tcp