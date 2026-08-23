# ByteTrail Frontend Dockerfile
FROM nginx:alpine

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy static frontend assets (HTML, CSS, JS)
COPY . /usr/share/nginx/html

# Expose port 80 (mapped to 3000 in compose)
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
