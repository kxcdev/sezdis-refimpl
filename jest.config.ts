import type { Config } from "jest";

const config: Config = {
  verbose: true,
  testPathIgnorePatterns: ["_tsout/"],
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        // ts-jest configuration goes here
      },
    ],
  },
};

export default config;
