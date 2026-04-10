import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from './models/User.js';

dotenv.config();

const seedDatabase = async () => {
  try {
    const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/medisiem';
    
    // Connect to MongoDB
    await mongoose.connect(MONGO_URI);
    console.log('✅  MongoDB connected');

    // Clear existing admin users
    await User.deleteMany({ role: 'admin' });
    console.log('🗑️  Cleared existing admin users');

    // Create admin user
    const admin = await User.create({
      name: 'System Administrator',
      email: 'admin@medisiem.com',
      password: 'Admin@1234',
      role: 'admin',
    });

    console.log('✅  Admin user created:');
    console.log(`   Email: ${admin.email}`);
    console.log(`   Password: Admin@1234`);
    console.log(`   Role: ${admin.role}`);

    // Create demo user
    const user = await User.create({
      name: 'Demo User',
      email: 'user@medisiem.com',
      password: 'User@1234',
      role: 'user',
    });

    console.log('\n✅  Demo user created:');
    console.log(`   Email: ${user.email}`);
    console.log(`   Password: User@1234`);
    console.log(`   Role: ${user.role}`);

    console.log('\n✅  Database seeded successfully!');
    process.exit(0);
  } catch (err) {
    console.error('❌  Error seeding database:', err.message);
    process.exit(1);
  }
};

seedDatabase();
