const Tag = require("../models/Tags");


// Create Tag ka handler function 

exports.createTag = async (req, res) => {
    try {
        // fetch data
        const { name, description } = req.body;

        // validation
        if (!name || !description) {
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }

        // create entry in DB
        const tagDetails = await Tag.create({
            name: name,
            description: description,
        });
        console.log(tagDetails);

        // return response
        return res.status(200).json({
            success: true,
            message: "Tag Created Successfully",
        });
    } 
    catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message,
        });
    }
}

// getAllTags handler function
exports.showAllTags = async (req, res) => {
    try {

        // fetch all tags
        const allTags = await Tag.find({}, { name: true, description: true });

        // return response
        return res.status(200).json({
            success: true,
            message: "All tags returned successfully",
            allTags,
        });
    }
    catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message,
        });
    }
}