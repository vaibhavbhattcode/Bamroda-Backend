const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const moment = require("moment");
const nodemailer = require("nodemailer");

// Configuring dotenv
dotenv.config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors({
  origin: ['https://bamroda.vercel.app', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Create uploads folder if it doesn't exist
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Serve uploaded files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("MongoDB connection error:", err));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ message: "Access denied. Token missing." });
  }

  // Remove "Bearer " prefix if present
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : authHeader;

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("Token verification failed:", err.message);
      if (err.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ message: "Session expired. Please log in again." });
      }
      return res
        .status(401)
        .json({ message: "Invalid token. Please log in again." });
    }
    req.userId = decoded.id || decoded.userId; // Use either field
    next();
  });
};

// User schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// Profile schema and model
const profileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  photo: { type: String },
  surname: { type: String, required: true },
  name: { type: String, required: true },
  fatherName: { type: String, required: true },
  dob: { type: Date, required: true },
  age: { type: Number, required: true },
  mobile: { type: String, required: true },
  address: { type: String, required: true },
  achievements: [
    {
      type: {
        type: String,
        enum: ["Academic", "Sports", "Professional", "Other"],
      },
      description: { type: String },
      year: { type: Number },
    },
  ],
  certificates: [{ type: String }],
});
const UserProfile = mongoose.model("UserProfile", profileSchema);

// Function to calculate age based on date of birth
const calculateAge = (dob) => {
  const today = new Date();
  const birthDate = new Date(dob);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDifference = today.getMonth() - birthDate.getMonth();

  // Adjust age if birthday hasn't occurred yet this year
  if (
    monthDifference < 0 ||
    (monthDifference === 0 && today.getDate() < birthDate.getDate())
  ) {
    age--;
  }
  return age;
};

// Verification schema and model
const verificationSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  code: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 }, // Expires in 5 minutes
});
const Verification = mongoose.model("Verification", verificationSchema);

// Send verification code
app.post("/send-verification", async (req, res) => {
  const { email } = req.body;
  const code = (Math.floor(Math.random() * 900000) + 100000).toString();
  await Verification.findOneAndUpdate({ email }, { code }, { upsert: true });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Email Verification Code",
    text: `Your verification code is: ${code}`,
  });

  res.json({ message: "Verification code sent" });
});

// Verify code
app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;
  const record = await Verification.findOne({ email, code });
  if (!record) return res.status(400).json({ message: "Invalid code" });

  res.json({ message: "Verified" });
});

// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { username, email, password, confirmPassword, code } = req.body;

    // Check if all fields are provided
    if (!username || !email || !password || !confirmPassword || !code) {
      return res.status(400).json({ message: "બધી વિગતો પૂરી કરો." });
    }

    // Validate password strength
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "પાસવર્ડ ઓછામાં ઓછો 6 અક્ષરનો હોવો જોઈએ." });
    }
    if (!/[A-Z]/.test(password)) {
      return res
        .status(400)
        .json({ message: "પાસવર્ડમાં ઓછામાં ઓછું એક કેપિટલ અક્ષર હોવો જોઈએ." });
    }
    if (!/[0-9]/.test(password)) {
      return res
        .status(400)
        .json({ message: "પાસવર્ડમાં ઓછામાં ઓછું એક નંબર હોવો જોઈએ." });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "પાસવર્ડ મેળ ખાતો નથી." });
    }

    // Check if email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "આ ઈમેલ પહેલેથી જ વપરાઈ રહ્યો છે." });
    }

    // Verify the code
    const verified = await Verification.findOne({ email, code });
    if (!verified) {
      return res.status(400).json({ message: "ઈમેલ વેરિફિકેશન કોડ ખોટો છે." });
    }

    // Delete verification entry after successful validation
    await Verification.deleteOne({ email, code });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user
    await new User({ username, email, password: hashedPassword }).save();

    res.status(201).json({ message: "રજિસ્ટ્રેશન સફળ થયું! 🎉" });
  } catch (error) {
    console.error("Error in registration:", error);

    if (error.code === 11000) {
      return res
        .status(400)
        .json({ message: "આ યુઝરનેમ અથવા ઈમેલ પહેલેથી જ વપરાઈ ગયો છે." });
    }

    res.status(500).json({ message: "સર્વર ભૂલ! પછીથી પ્રયત્ન કરો." });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(403).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({ token });
  } catch (err) {
    console.error("Error logging in:", err);
    res.status(500).json({ message: "Error logging in" });
  }
});

app.get("/get-user", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("username");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ username: user.username });
  } catch (err) {
    console.error("Error in /get-user:", err);
    res.status(500).json({ message: "Error retrieving user" });
  }
});

// Fetch profile endpoint
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const profile = await UserProfile.findOne({ userId: req.userId });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    const formattedProfile = {
      ...profile.toObject(),
      dob: profile.dob
        ? profile.dob.toISOString().split("T")[0].split("-").reverse().join("-")
        : "",
    };

    res.status(200).json(formattedProfile);
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ message: "Error fetching profile" });
  }
});

// Update profile endpoint
app.post(
  "/update-profile",
  verifyToken,
  upload.fields([{ name: "photo" }, { name: "certificates" }]),
  async (req, res) => {
    const userId = req.userId;
    let { surname, name, fatherName, dob, mobile, address, achievements } =
      req.body;

    try {
      // Parse and validate DOB
      if (dob) {
        const dobParts = dob.split("-");
        if (dobParts.length !== 3) {
          return res
            .status(400)
            .send("Invalid date format. Expected dd-mm-yyyy.");
        }

        const formattedDob = new Date(
          `${dobParts[2]}-${dobParts[1]}-${dobParts[0]}`
        );

        if (isNaN(formattedDob.getTime())) {
          return res.status(400).send("Invalid date.");
        }

        dob = formattedDob;
      }

      // Calculate age
      const age = calculateAge(dob);

      // Fetch existing profile
      const existingProfile = await UserProfile.findOne({ userId });

      const updatedProfile = {
        surname,
        name,
        fatherName,
        dob,
        age,
        mobile,
        address,
        achievements: achievements ? JSON.parse(achievements) : [],
      };

      // Handle certificates and photo logic
      let existingCertificates = existingProfile
        ? existingProfile.certificates || []
        : [];

      if (req.files["certificates"]) {
        const newCertificates = req.files["certificates"].map(
          (file) => file.filename
        );
        existingCertificates = [...existingCertificates, ...newCertificates];
      }

      const { certificatesToDelete } = req.body;
      if (certificatesToDelete) {
        const certificatesToRemove = JSON.parse(certificatesToDelete);

        certificatesToRemove.forEach((certificate) => {
          const filePath = path.join(__dirname, "uploads", certificate);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        });

        existingCertificates = existingCertificates.filter(
          (certificate) => !certificatesToRemove.includes(certificate)
        );
      }

      updatedProfile.certificates = existingCertificates;

      if (req.files["photo"]) {
        updatedProfile.photo = req.files["photo"][0].filename;
      }

      // Update or create profile
      const profile = await UserProfile.findOneAndUpdate(
        { userId },
        updatedProfile,
        { new: true, upsert: true }
      );

      // Update or create villager
      const fullName = `${surname} ${name} ${fatherName}`.trim();
      await Villager.findOneAndUpdate(
        { userId },
        { fullName },
        { new: true, upsert: true }
      );

      res.status(200).json({
        message: "Profile and villager updated successfully",
        profile,
      });
    } catch (error) {
      console.error("Error updating profile:", error);
      res.status(500).send("Error updating profile");
    }
  }
);

const villagerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "UserProfile",
    required: true,
  },
  fullName: { type: String, required: true },
});

const Villager = mongoose.model("Villager", villagerSchema);

// Centralized error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res
    .status(500)
    .json({ message: "Something went wrong!", error: err.message });
});

// Fetch villager suggestions endpoint
app.get("/api/villagers", async (req, res) => {
  const searchQuery = req.query.search;

  if (!searchQuery) {
    return res.status(400).json({ message: "Search query is required." });
  }

  try {
    const villagers = await Villager.find({
      fullName: { $regex: searchQuery, $options: "i" },
    }).select("userId fullName");

    res.status(200).json(villagers);
  } catch (error) {
    console.error("Error fetching villagers:", error);
    res.status(500).json({ message: "Error fetching villagers." });
  }
});

// Fetch a specific villager's profile endpoint
app.get("/api/villager/:id", async (req, res) => {
  const villagerId = req.params.id;

  try {
    const profile = await UserProfile.findOne({ userId: villagerId });

    if (!profile) {
      return res.status(404).json({ message: "Profile not found." });
    }

    const formattedProfile = {
      ...profile.toObject(),
      dob: profile.dob
        ? profile.dob.toISOString().split("T")[0].split("-").reverse().join("-")
        : "",
    };

    res.status(200).json(formattedProfile);
  } catch (error) {
    console.error("Error fetching villager profile:", error);
    res.status(500).json({ message: "Error fetching profile." });
  }
});

// Admin Schema and Model
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const Admin = mongoose.model("Admin", adminSchema);

// Admin Registration
app.post("/admin/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ message: "Admin already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ username, email, password: hashedPassword });
    await newAdmin.save();
    res.status(201).json({ message: "Admin registered successfully" });
  } catch (err) {
    console.error("Error registering admin:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Admin Login
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(403).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    res.status(200).json({ token });
  } catch (err) {
    console.error("Error logging in admin:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Verify Admin Token
app.get("/admin/me", verifyToken, async (req, res) => {
  try {
    const admin = await Admin.findById(req.userId).select("username email");
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    res.status(200).json(admin);
  } catch (err) {
    console.error("Error fetching admin details:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Fetch all registered users with profile completion status
app.get("/admin/users", verifyToken, async (req, res) => {
  try {
    const users = await User.find().select("_id username email");

    // Map through users and check if they have a completed profile
    const usersWithProfileStatus = await Promise.all(
      users.map(async (user) => {
        const profile = await UserProfile.findOne({ userId: user._id });

        // Define criteria for a completed profile
        const isProfileCompleted =
          profile &&
          profile.surname &&
          profile.name &&
          profile.fatherName &&
          profile.dob &&
          profile.age &&
          profile.mobile &&
          profile.address;

        return {
          id: user._id,
          username: user.username,
          email: user.email,
          profileCompleted: isProfileCompleted ? true : false,
        };
      })
    );

    res.status(200).json(usersWithProfileStatus);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Error fetching users" });
  }
});

// Fetch all created profiles
app.get("/admin/profiles", verifyToken, async (req, res) => {
  try {
    const profiles = await UserProfile.find().populate(
      "userId",
      "username email"
    );
    res.status(200).json(profiles);
  } catch (err) {
    console.error("Error fetching profiles:", err);
    res.status(500).json({ message: "Error fetching profiles" });
  }
});

// Fetch admin dashboard statistics
app.get("/admin/stats", verifyToken, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();

    // Count only profiles that meet the required fields criteria
    const profileCompletedUsers = await UserProfile.countDocuments({
      surname: { $exists: true, $ne: "" },
      name: { $exists: true, $ne: "" },
      fatherName: { $exists: true, $ne: "" },
      dob: { $exists: true, $ne: null },
      age: { $exists: true, $ne: null },
      mobile: { $exists: true, $ne: "" },
      address: { $exists: true, $ne: "" },
    });

    res.status(200).json({
      totalUsers,
      profileCompletedUsers,
    });
  } catch (err) {
    console.error("Error fetching stats:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Fetch all users from Villager collection
app.get("/admin/userlist", verifyToken, async (req, res) => {
  try {
    const villagers = await Villager.find().select("_id fullName userId");
    res.status(200).json(villagers);
  } catch (err) {
    console.error("Error fetching villagers:", err);
    res.status(500).json({ message: "Error fetching villagers" });
  }
});

// Update Villager Profile
app.put("/admin/villager/:id", verifyToken, async (req, res) => {
  try {
    const updatedVillager = await Villager.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updatedVillager) {
      return res.status(404).json({ message: "Villager not found" });
    }
    res.status(200).json(updatedVillager);
  } catch (err) {
    console.error("Error updating villager:", err);
    res.status(500).json({ message: "Error updating villager" });
  }
});

// Delete Villager
app.delete("/admin/villager/:id", verifyToken, async (req, res) => {
  try {
    const deletedVillager = await Villager.findByIdAndDelete(req.params.id);
    if (!deletedVillager) {
      return res.status(404).json({ message: "Villager not found" });
    }
    res.status(200).json({ message: "Villager deleted successfully" });
  } catch (err) {
    console.error("Error deleting villager:", err);
    res.status(500).json({ message: "Error deleting villager" });
  }
});

app.get("/api/userprofile/:id", async (req, res) => {
  try {
    const profile = await UserProfile.findOne({ userId: req.params.id });

    if (!profile) {
      return res.status(404).json({ message: "Profile not found." });
    }

    res.status(200).json(profile);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ message: "Error fetching profile" });
  }
});

// Fetch villagers with today's birthday
app.get("/birthdays", async (req, res) => {
  try {
    const today = moment().format("YYYY-MM-DD");
    const villagers = await UserProfile.find({
      dob: { $exists: true, $ne: null },
    }).populate("userId", "email");

    const birthdayVillagers = villagers.filter((villager) => {
      return moment(villager.dob).format("MM-DD") === moment().format("MM-DD");
    });

    res.status(200).json(birthdayVillagers);
  } catch (error) {
    console.error("Error fetching birthdays:", error);
    res.status(500).json({ message: "Error fetching birthdays." });
  }
});

// Send birthday wish email
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587, // Use port 587 for TLS
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

const gujaratiMessages = [
  "તમારા જીવનમાં ખુશીઓ અને સમૃદ્ધિ ભરેલા દિવસો આવે! જન્મદિવસની શુભેચ્છાઓ! 🎂✨",
  "તમારા માટે આ નવો વર્ષ આનંદમય અને ઉર્જાથી ભરપૂર રહે! જન્મદિવસની હાર્દિક શુભકામનાઓ! 🎉",
  "તમારા સપનાઓ સાકાર થાય અને તમારું જીવન ખુશીઓથી ભરપૂર રહે! જન્મદિવસ મુબારક! 🎁",
  "આજનો દિવસ તમને એક નવી ઉર્જા અને આનંદ ભરી યાદગિરી આપે! જન્મદિવસની હાર્દિક શુભકામનાઓ! 🎂🎈",
  "સફળતા અને ખુશીઓના નવા દ્વાર ખુલે! જન્મદિવસની મંગળકામનાઓ! 🎉🌸",
  "તમારા જીવનમાં પ્રેમ, શાંતિ અને સુખ સમૃદ્ધિ વધતી રહે! હેપ્પી બર્થડે! 🎂❤️",
  "તમે હંમેશા હસતા રહો અને તમારું જીવન હંમેશા ઉજ્જવળ બને! જન્મદિવસની શુભેચ્છાઓ! 🎁🎊",
  "તમારા દરેક સપનાને નવી ઉડાન મળે અને તમારું જીવન આશીર્વાદોથી ભરેલું રહે! હેપ્પી બર્થડે! 🎉🌟",
];

const gujaratiQuotes = [
  "સફળતા એ એક યાત્રા છે, ગંતવ્ય નહીં. દરેક પગલું મહત્વનું છે.",
  "તમારા સપનાને હકીકતમાં બદલવા માટે આજે એક નવો પ્રારંભ કરો.",
  "મહાન વસ્તુઓ હંમેશા તમારા આરામ ક્ષેત્રની બહાર શરૂ થાય છે.",
  "તમે જે પણ ઈચ્છો, તે હકીકત બનશે – બસ વિશ્વાસ અને મહેનત જાળવી રાખો! 💪✨",
  "જન્મદિવસ એ જીવનના નવું શીખવા અને આગળ વધવા માટેનો એક મોકો છે. 📚🎈",
  "આજનો દિવસ તમારા જીવનની નવી ઊંચાઈઓ સર કરવા માટે એક પ્રેરણા બને! 🏆🎉",
];

// Function to send birthday email
const sendBirthdayWish = async (email, surname, name, fatherName) => {
  try {
    console.log(
      `📧 Sending email to: ${email} for ${surname} ${name} ${fatherName}`
    );

    const fullName = `${surname} ${name} ${fatherName}`;
    const randomMessage =
      gujaratiMessages[Math.floor(Math.random() * gujaratiMessages.length)];
    const randomQuote =
      gujaratiQuotes[Math.floor(Math.random() * gujaratiQuotes.length)];

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "🎉 જન્મદિવસની શુભકામનાઓ! 🎂",
      text: `પ્રિય ${fullName}જી,\n\n${randomMessage}\n\n🌟 ${randomQuote}\n\n✨ બમરોડા ગામ પરિવાર ✨`,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent successfully to ${fullName}: ${info.response}`);
    return info.messageId;
  } catch (error) {
    console.error(`❌ Error sending email:`, error);
    return null;
  }
};

// Automatically send wishes at midnight
setInterval(async () => {
  try {
    console.log("🔄 Checking for today's birthdays...");
    const villagers = await UserProfile.find({
      dob: { $exists: true, $ne: null },
    })
      .select("surname name fatherName dob userId")
      .populate({ path: "userId", select: "email" });

    const todayBirthdays = villagers.filter((villager) => {
      return moment(villager.dob).format("MM-DD") === moment().format("MM-DD");
    });

    if (todayBirthdays.length === 0) {
      console.log("📅 No birthdays today.");
      return;
    }

    for (const villager of todayBirthdays) {
      if (!villager.userId || !villager.userId.email) {
        console.error(`❌ Missing email for: ${villager.name}`);
        continue;
      }
      await sendBirthdayWish(
        villager.userId.email,
        villager.surname || "N/A",
        villager.name || "N/A",
        villager.fatherName || "N/A"
      );
    }
  } catch (error) {
    console.error("❌ Error in birthday email automation:", error);
  }
}, 24 * 60 * 60 * 1000); // Runs every 24 hours

app.get("/send-birthday-emails", async (req, res) => {
  try {
    const villagers = await UserProfile.find({
      dob: { $exists: true, $ne: null },
    })
      .select("surname name fatherName dob userId")
      .populate("userId", "email");

    const todayBirthdays = villagers.filter((villager) => {
      return moment(villager.dob).format("MM-DD") === moment().format("MM-DD");
    });

    if (todayBirthdays.length === 0) {
      return res.status(200).json({ message: "No birthdays today." });
    }

    for (const villager of todayBirthdays) {
      if (!villager.userId || !villager.userId.email) {
        console.error(`❌ Missing email for: ${villager.name}`);
        continue;
      }
      await sendBirthdayWish(
        villager.userId.email,
        villager.surname || "N/A",
        villager.name || "N/A",
        villager.fatherName || "N/A"
      );
    }

    res.status(200).json({ message: "Birthday emails sent successfully!" });
  } catch (error) {
    console.error("❌ Error sending birthday emails:", error);
    res.status(500).json({ message: "Error sending birthday emails." });
  }
});

// --------------------- Category and Image Endpoints ----------------------

// Category Schema and Model
const categorySchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
});
const Category = mongoose.model("GalleryCategory", categorySchema);

// Image Schema and Model
const imageSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  category: { type: String, required: true },
  uploadedAt: { type: Date, default: Date.now },
});
const Image = mongoose.model("GalleryImage", imageSchema);

// Fetch all categories
app.get("/api/categories", async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(categories.map((cat) => cat.name));
  } catch (error) {
    res.status(500).json({ message: "કેટેગરી લાવવામાં મુંજવણ થઈ!" });
  }
});

// Add a new category
app.post("/api/categories", async (req, res) => {
  const { category } = req.body;
  if (!category)
    return res.status(400).json({ message: "કૃપા કરીને કેટેગરી આપો!" });

  try {
    await Category.create({ name: category });
    res.status(200).json({ message: "કેટેગરી સફળતાપૂર્વક ઉમેરાઈ!" });
  } catch (error) {
    res.status(500).json({ message: "કેટેગરી ઉમેરવામાં સમસ્યા!" });
  }
});

// Delete a category and its associated images
app.delete("/api/categories/:category", async (req, res) => {
  const { category } = req.params;

  try {
    // Delete the category document
    const deleted = await Category.findOneAndDelete({ name: category });
    if (!deleted) {
      return res.status(404).json({ message: "કેટેગરી મળતી નથી!" });
    }

    // Find all images associated with the category
    const imagesToDelete = await Image.find({ category });

    // Delete each file from the uploads folder
    for (const image of imagesToDelete) {
      const filePath = path.join(__dirname, "uploads", image.filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    // Remove all image documents from the database
    await Image.deleteMany({ category });

    res.status(200).json({
      message: "કેટેગરી અને તેની જોડાયેલી ઈમેજીસ સફળતાપૂર્વક ડિલીટ થઈ!",
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "કેટેગરી ડિલીટ કરવામાં સમસ્યા!", error: error.message });
  }
});

// Upload Images
app.post("/api/upload-images", upload.array("images", 10), async (req, res) => {
  const { category } = req.body;
  if (!category)
    return res.status(400).json({ message: "કૃપા કરીને કેટેગરી પસંદ કરો!" });
  if (!req.files || req.files.length === 0)
    return res.status(400).json({ message: "કોઈ ફાઈલ અપલોડ થઈ નથી." });

  try {
    const uploadedImages = req.files.map((file) => ({
      filename: file.filename,
      category,
    }));
    await Image.insertMany(uploadedImages);
    res.status(200).json({ message: "તસવીરો સફળતાપૂર્વક અપલોડ થઈ ગઈ!" });
  } catch (error) {
    res.status(500).json({ message: "તસવીરો અપલોડ કરવામાં મુંજવણ!" });
  }
});

// Fetch Images
app.get("/api/gallery", async (req, res) => {
  try {
    const images = await Image.find();
    const categorizedImages = {};
    images.forEach(({ category, filename, _id }) => {
      if (!categorizedImages[category]) categorizedImages[category] = [];
      categorizedImages[category].push({ filename, _id });
    });
    res.json(categorizedImages);
  } catch (error) {
    res.status(500).json({ message: "તસવીરો લાવવામાં મુંજવણ!" });
  }
});

// Delete Image
app.delete("/api/delete-image/:id", async (req, res) => {
  try {
    const image = await Image.findByIdAndDelete(req.params.id);
    if (!image) return res.status(404).json({ message: "ઈમેજ મળતી નથી!" });

    // Remove file from uploads folder
    const filePath = path.join(__dirname, "uploads", image.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    res.status(200).json({ message: "ઈમેજ સફળતાપૂર્વક ડિલીટ થઈ!" });
  } catch (error) {
    res.status(500).json({ message: "ઈમેજ ડિલીટ કરવામાં મુંજવણ!" });
  }
});

// Blog Category Schema
const blogCategorySchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
});
const BlogCategory = mongoose.model("BlogCategory", blogCategorySchema);

// Blog Post Schema
const blogPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  coverImage: { type: String, required: true },
  content: { type: String, required: true },
  images: [{ type: String }],
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BlogCategory",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});
const BlogPost = mongoose.model("BlogPost", blogPostSchema);

// Create a new category
app.post("/api/blog-categories", verifyToken, async (req, res) => {
  const { name } = req.body;
  if (!name)
    return res.status(400).json({ message: "Category name is required" });
  try {
    const category = await BlogCategory.create({ name });
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ message: "Error creating category" });
  }
});

// Fetch all categories
app.get("/api/blog-categories", async (req, res) => {
  try {
    const categories = await BlogCategory.find({}, "_id name");
    res.status(200).json(categories);
  } catch (error) {
    res.status(500).json({ message: "Error fetching categories" });
  }
});

// Delete a category
app.delete("/api/blog-categories/:id", verifyToken, async (req, res) => {
  try {
    const category = await BlogCategory.findByIdAndDelete(req.params.id);
    if (!category)
      return res.status(404).json({ message: "Category not found" });
    res.status(200).json({ message: "Category deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting category" });
  }
});

/// Create a new blog post
app.post(
  "/api/blog-posts",
  verifyToken,
  // Use the field name "contentImages" for the new content images
  upload.fields([{ name: "coverImage" }, { name: "contentImages" }]),
  async (req, res) => {
    try {
      const { title, content, category } = req.body;
      if (!title || !content || !category)
        return res.status(400).json({ message: "All fields are required" });

      // Process the cover image
      const coverImage = req.files["coverImage"]
        ? req.files["coverImage"][0].filename
        : null;
      // Process the new content images
      const contentImages = req.files["contentImages"]
        ? req.files["contentImages"].map((file) => file.filename)
        : [];

      const blogPost = new BlogPost({
        title,
        coverImage,
        content,
        images: contentImages, // Save the new content images in the "images" field of the blog post
        category,
      });
      await blogPost.save();
      res.status(201).json(blogPost);
    } catch (error) {
      console.error("Error creating blog post:", error);
      res.status(500).json({ message: "Error creating blog post" });
    }
  }
);

app.post(
  "/api/upload-image",
  verifyToken,
  upload.single("image"),
  (req, res) => {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });
    res.status(200).json({ filename: req.file.filename });
  }
);

// Fetch all blog posts
app.get("/api/blog-posts", async (req, res) => {
  try {
    const blogPosts = await BlogPost.find().populate("category", "name");
    res.status(200).json(blogPosts);
  } catch (error) {
    res.status(500).json({ message: "Error fetching blog posts" });
  }
});
app.get("/api/blog-posts/:id", async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id).populate("category");
    if (!post) return res.status(404).json({ message: "Post not found" });

    res.json(post);
  } catch (error) {
    res.status(500).json({ message: "Error fetching post" });
  }
});

// Edit a blog post
app.put(
  "/api/blog-posts/:id",
  verifyToken,
  // Expect the same field names for uploads
  upload.fields([{ name: "coverImage" }, { name: "contentImages" }]),
  async (req, res) => {
    try {
      const post = await BlogPost.findById(req.params.id);
      if (!post) {
        return res.status(404).json({ message: "Post not found" });
      }

      // --- Handle cover image updates ---
      if (req.files["coverImage"]) {
        // Delete the old cover image file if it exists
        if (post.coverImage) {
          const oldFilePath = path.join(__dirname, "uploads", post.coverImage);
          if (fs.existsSync(oldFilePath)) fs.unlinkSync(oldFilePath);
        }
        post.coverImage = req.files["coverImage"][0].filename;
      }

      // --- Handle new content images ---
      // Process newly uploaded content images (if any)
      let newContentImages = [];
      if (req.files["contentImages"]) {
        newContentImages = req.files["contentImages"].map(
          (file) => file.filename
        );
      }
      // The frontend should send the remaining (or existing) images as a JSON string
      const existingImages = req.body.existingImages
        ? JSON.parse(req.body.existingImages)
        : [];
      // Combine existing images (that were not removed) with newly uploaded ones
      post.images = existingImages.concat(newContentImages);

      // --- Update other fields ---
      post.title = req.body.title || post.title;
      post.content = req.body.content || post.content;
      post.category = req.body.category || post.category;

      const updatedPost = await post.save();
      res.json(updatedPost);
    } catch (error) {
      console.error("Error updating post:", error);
      res.status(500).json({ message: "Error updating post" });
    }
  }
);

// Delete Blog Post (unchanged)
app.delete("/api/blog-posts/:id", verifyToken, async (req, res) => {
  try {
    const deletedPost = await BlogPost.findByIdAndDelete(req.params.id);
    if (!deletedPost)
      return res.status(404).json({ message: "Post not found" });

    // Delete associated files (cover image and content images)
    if (deletedPost.coverImage) {
      const coverPath = path.join(__dirname, "uploads", deletedPost.coverImage);
      if (fs.existsSync(coverPath)) fs.unlinkSync(coverPath);
    }
    deletedPost.images.forEach((image) => {
      const imagePath = path.join(__dirname, "uploads", image);
      if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
    });

    res.status(200).json({ message: "Post deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting post" });
  }
});

// --------------------- Events Endpoints ----------------------

// Event Schema and Model
const eventSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String },
    location: { type: String },
    date: { type: Date, required: true },
    image: { type: String }, // stores the filename of the uploaded image
  },
  { timestamps: true }
);
const Event = mongoose.model("Event", eventSchema);

// Get single event by ID (needed for editing)
app.get("/api/events/:id", async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });
    res.status(200).json(event);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching event", error: error.message });
  }
});

// Create a new event (Admin Only) with file upload support
app.post(
  "/api/events",
  verifyToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, description, location, date } = req.body;
      const image = req.file ? req.file.filename : "";
      const event = new Event({ title, description, location, date, image });
      await event.save();
      res.status(201).json({ message: "Event created successfully", event });
    } catch (error) {
      console.error("Error creating event:", error);
      res
        .status(500)
        .json({ message: "Error creating event", error: error.message });
    }
  }
);

// Update an event (Admin Only) with file upload support
app.put(
  "/api/events/:id",
  verifyToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const event = await Event.findById(req.params.id);
      if (!event) return res.status(404).json({ message: "Event not found" });
      const { title, description, location, date } = req.body;
      if (title) event.title = title;
      if (description) event.description = description;
      if (location) event.location = location;
      if (date) event.date = date;
      if (req.file) {
        // Delete old image if exists
        if (event.image) {
          const oldPath = path.join(__dirname, "uploads", event.image);
          if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        event.image = req.file.filename;
      }
      await event.save();
      res.status(200).json({ message: "Event updated successfully", event });
    } catch (error) {
      console.error("Error updating event:", error);
      res
        .status(500)
        .json({ message: "Error updating event", error: error.message });
    }
  }
);

// Delete an event (Admin Only)
app.delete("/api/events/:id", verifyToken, async (req, res) => {
  try {
    const event = await Event.findByIdAndDelete(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });
    if (event.image) {
      const imagePath = path.join(__dirname, "uploads", event.image);
      if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
    }
    res.status(200).json({ message: "Event deleted successfully" });
  } catch (error) {
    console.error("Error deleting event:", error);
    res
      .status(500)
      .json({ message: "Error deleting event", error: error.message });
  }
});

// Retrieve all events (Public)
app.get("/api/events", async (req, res) => {
  try {
    const events = await Event.find().sort({ date: 1 });
    res.status(200).json(events);
  } catch (error) {
    console.error("Error fetching events:", error);
    res
      .status(500)
      .json({ message: "Error fetching events", error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
