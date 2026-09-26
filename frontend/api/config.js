// Vercel Serverless Function to expose Vercel environment variables to frontend
module.exports = (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control", "s-maxage=60, stale-while-revalidate");
    res.status(200).json({
        API_BASE_URL: process.env.API_BASE_URL || "https://universal-log-preprocessor.onrender.com"
    });
};
