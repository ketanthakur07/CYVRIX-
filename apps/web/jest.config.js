/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: "jest-environment-jsdom",
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/$1",
  },
  transform: {
    "^.+\\.(ts|tsx)$": [
      "ts-jest",
      {
        tsconfig: {
          jsx: "react-jsx",
          module: "esnext",
          moduleResolution: "bundler",
          esModuleInterop: true,
          strict: true,
          target: "es2020",
          paths: { "@/*": ["./*"] },
        },
      },
    ],
  },
  testMatch: ["<rootDir>/__tests__/**/*.test.(ts|tsx)"],
};
