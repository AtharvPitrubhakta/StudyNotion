const mongoose = require('mongoose');

const courseSchema = new mongoose.Schema({

    courseName: {
        type: String,
        required: true,
    },
    courseDescription: {
        type: String,
        trim: true,
    },
    instructor: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
    },
    whatYouWillLearn:{
        type: String,
    },
    courseContent: [
        {
            type: mongoose.Schema.Types.ObjectId,   
            ref: "Section"
        }
    ],
    ratingAndReviews: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "RatingAndReviews",
        }
    ],
    price: {
        type: Number, 
    },
    thumbnail: {
        type: String,
    },
    tag: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Tag",
    },
    studentsEnrolled: [{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "User",
    }]
});


module.exports = mongoose.model("Course", courseSchema)