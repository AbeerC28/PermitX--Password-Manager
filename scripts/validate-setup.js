#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔍 Validating Auth Password Manager Setup...\n');

const checks = [
  {
    name: 'Package.json exists',
    check: () => fs.existsSync('package.json'),
  },
  {
    name: 'TypeScript config exists',
    check: () => fs.existsSync('tsconfig.json'),
  },
  {
    name: 'Environment config exists',
    check: () => fs.existsSync('.env'),
  },
  {
    name: 'Source directory structure',
    check: () => {
      const dirs = ['src/config', 'src/models', 'src/services', 'src/controllers'];
      return dirs.every(dir => fs.existsSync(dir));
    },
  },
  {
    name: 'Client directory exists',
    check: () => fs.existsSync('client'),
  },
  {
    name: 'Client package.json exists',
    check: () => fs.existsSync('client/package.json'),
  },
  {
    name: 'Build output exists',
    check: () => fs.existsSync('dist'),
  },
  {
    name: 'Client build output exists',
    check: () => fs.existsSync('client/dist'),
  },
];

let passed = 0;
let failed = 0;

checks.forEach(({ name, check }) => {
  try {
    if (check()) {
      console.log(`✅ ${name}`);
      passed++;
    } else {
      console.log(`❌ ${name}`);
      failed++;
    }
  } catch (error) {
    console.log(`❌ ${name} (Error: ${error.message})`);
    failed++;
  }
});

console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);

if (failed === 0) {
  console.log('🎉 Setup validation completed successfully!');
  console.log('\n📝 Next steps:');
  console.log('1. Start MongoDB and Redis: npm run docker:dev');
  console.log('2. Start development server: npm run dev');
  console.log('3. Open http://localhost:3000 in your browser');
} else {
  console.log('⚠️  Some checks failed. Please review the setup.');
  process.exit(1);
}