// In-memory user store — passwords bcrypt hashed, plain-text shown in comments.
// Default credentials: admin@medisiem.com/Admin@1234, user@medisiem.com/User@1234
import bcrypt from 'bcryptjs';

const hashSync = (pw) => bcrypt.hashSync(pw, 10);

export let users = [
  {
    id: '1',
    name: 'System Administrator',
    email: 'admin@medisiem.com',
    password: hashSync('Admin@1234'),
    role: 'admin',
    createdAt: new Date('2025-01-01').toISOString(),
  },
  {
    id: '2',
    name: 'SOC Analyst',
    email: 'user@medisiem.com',
    password: hashSync('User@1234'),
    role: 'user',
    createdAt: new Date('2025-03-01').toISOString(),
  },
];
