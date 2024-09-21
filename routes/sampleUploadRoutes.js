/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

/**

const express = require('express');
const multer = require('multer');
const { check, validationResult } = require('express-validator');

const studentController = require('../controllers/studentController');

// express app
const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/'); // Define the upload directory
    },
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}_${file.originalname}`);
    }
});
const upload = multer({ storage });

// view student
router.get('/', studentController.index);
// Create a new student
router.get('/new', studentController.new_student);
router.post('/create', upload.single('photo'), studentController.createStudent);

// Edit student form
router.get('/edit/:id', studentController.getEditForm);

// Update student
router.post('/update/:id', upload.single('photo'), [
    check('firstName').not().isEmpty().withMessage('First Name is required'),
    check('idNumber').not().isEmpty().withMessage('ID Number is required'),
    check('yearLevel').not().isEmpty().withMessage('Year Level is required'),
    check('section').not().isEmpty().withMessage('Section is required'),
    check('semester').not().isEmpty().withMessage('Semester is required'),
    check('acadYear').not().isEmpty().withMessage('Academic Year is required')
], studentController.updateStudent);


// Import students from Excel file
router.get('/import', studentController.getImportForm);
router.post('/import', upload.single('file'), studentController.importStudents);

module.exports = router;



 */