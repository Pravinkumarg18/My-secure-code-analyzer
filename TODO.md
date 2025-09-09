# Deployment Plan for Secure Code Analyzer

## Backend Deployment (Flask) - Render.com
- [x] Create render.yaml configuration file
- [x] Create requirements.txt for production (if needed)
- [x] Build React app for production
- [x] Push code to GitHub
- [ ] Deploy backend to Render.com (manual step required)
- [ ] Get production API URL from Render.com dashboard

## Frontend Deployment (React) - Vercel
- [ ] Build React app for production using `npm run build`
- [ ] Update config.js or set environment variable `REACT_APP_API_URL` with backend production URL
- [ ] Deploy frontend to Vercel (manual step required)
- [ ] Test full application

## Testing
- [ ] Verify backend API endpoints work on Render.com
- [ ] Verify frontend loads and connects to backend
- [ ] Test file upload and scanning functionality
