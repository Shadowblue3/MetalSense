const mongoose = require('mongoose');
require('dotenv').config();

// Use the environment variable
const connection = mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("connected to mongodb");
}).catch(err => {
    console.error("Error connecting to MongoDB:", err.message);
});

module.exports = connection;
