require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase setup
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Middleware
app.use(cors({ origin: '*' })); // Restrict origin for production
app.use(bodyParser.json());

// Route: Register User
app.post(
    '/register',
    [
        body('fullName').isLength({ min: 3 }).withMessage('Full name must be at least 3 characters long'),
        body('email').isEmail().withMessage('Invalid email address'),
        body('phone').isMobilePhone().withMessage('Invalid phone number'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
        body('anonymous').isBoolean().withMessage('Anonymous status must be a boolean'),
        body('isOfficer').isBoolean().withMessage('isOfficer must be a boolean'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { fullName, email, phone, password, anonymous, isOfficer } = req.body;

        try {
            // Check if user already exists
            const { data: existingUser } = await supabase
                .from('users')
                .select('id')
                .eq('email', email)
                .single();

            if (existingUser) {
                return res.status(400).json({ message: 'Email is already registered.' });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user into the database
            const { error } = await supabase.from('users').insert([
                {
                    full_name: fullName,
                    email,
                    phone,
                    password: hashedPassword,
                    role: isOfficer ? 'Law Enforcement Officer' : 'Citizen',
                    anonymous_status: anonymous,
                    officer_verification: isOfficer ? false : null,
                    verification_status: false, // Updated after OTP verification
                },
            ]);

            if (error) {
                throw new Error('Failed to register user');
            }

            res.status(200).json({ message: 'Registration successful. Please verify your phone.' });
        } catch (error) {
            console.error('Error registering user:', error.message);
            res.status(500).json({ message: 'Internal server error.' });
        }
    }
);

// Route: Send OTP for Phone Verification
app.post('/send-otp', async (req, res) => {
    const { phone } = req.body;

    if (!phone) {
        return res.status(400).json({ message: 'Phone number is required.' });
    }

    try {
        const { error } = await supabase.auth.signInWithOtp({ phone });

        if (error) {
            throw new Error('Failed to send OTP');
        }

        res.status(200).json({ message: 'OTP sent successfully.' });
    } catch (error) {
        console.error('Error sending OTP:', error.message);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// Route: Verify OTP
app.post('/verify-otp', async (req, res) => {
    const { phone, token } = req.body;

    if (!phone || !token) {
        return res.status(400).json({ message: 'Phone and OTP token are required.' });
    }

    try {
        const { error } = await supabase.auth.verifyOtp({
            phone,
            token,
            type: 'sms',
        });

        if (error) {
            throw new Error('Invalid OTP');
        }

        // Mark the user's phone as verified in the database
        const { error: updateError } = await supabase
            .from('users')
            .update({ verification_status: true })
            .eq('phone', phone);

        if (updateError) {
            throw new Error('Failed to update verification status');
        }

        res.status(200).json({ message: 'Phone verified successfully.' });
    } catch (error) {
        console.error('Error verifying OTP:', error.message);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
