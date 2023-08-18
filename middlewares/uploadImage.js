const multer = require('multer');
const path=require('path');
const fs = require('fs');
const { StatusCodes } = require('http-status-codes');

const dirPath = path.join('public','images');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null,dirPath);
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

async function createDirectoryIfNotExists(path){
  try {
    await fs.promises.access(path, fs.constants.F_OK);
  } catch (error) {
    await new Promise((resolve, reject) => {
      fs.mkdir(path, { recursive: true }, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }
}

const uploadImage = async(req, res, next) => {

    await createDirectoryIfNotExists(dirPath);
    upload.single('image')(req, res, (err) => {
        if (err instanceof multer.MulterError) {
          return res.status(StatusCodes.BAD_REQUEST).json({ error: err.message });
        } else if (err) {
          return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: err.message });
        }
        next();
    });
};

module.exports=uploadImage;

