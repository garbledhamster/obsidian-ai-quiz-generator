export type QuestionTypeSettings = {
  matchingEnabled: boolean;
  matchingQuantity: number;
  selectAllEnabled: boolean;
  selectAllQuantity: number;
  fillBlankEnabled: boolean;
  fillBlankQuantity: number;
  multipleChoiceEnabled: boolean;
  multipleChoiceQuantity: number;
  trueFalseEnabled: boolean;
  trueFalseQuantity: number;
  shortLongEnabled: boolean;
  shortLongQuantity: number;
};

export type QuestionTypeRegistryEntry = {
  enabledToggleKey: keyof QuestionTypeSettings;
  quantityKey: keyof QuestionTypeSettings;
  description: string;
  schemaShape: string;
  typeGuard: (value: unknown) => boolean;
};

export const MULTIPLE_CHOICE_TOGGLE_KEY: QuestionTypeRegistryEntry["enabledToggleKey"] = "multipleChoiceEnabled";

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;
const isString = (value: unknown): value is string => typeof value === "string";
const isNumber = (value: unknown): value is number => Number.isFinite(value);
const isBoolean = (value: unknown): value is boolean => typeof value === "boolean";
const isStringArray = (value: unknown): value is string[] => Array.isArray(value) && value.every(isString);
const isNumberArray = (value: unknown): value is number[] => Array.isArray(value) && value.every(isNumber);

const isMatchingQuestion = (value: unknown): boolean => {
  if (!isRecord(value)) return false;
  if (!isString(value.prompt)) return false;
  if (!Array.isArray(value.pairs) || value.pairs.length === 0) return false;
  return value.pairs.every((pair) => {
    if (!isRecord(pair)) return false;
    return isString(pair.left) && isString(pair.right);
  });
};

const isSelectAllQuestion = (value: unknown): boolean => {
  if (!isRecord(value)) return false;
  return isString(value.q)
    && isStringArray(value.choices)
    && isNumberArray(value.correct_indexes)
    && value.correct_indexes.length > 0;
};

const isFillBlankQuestion = (value: unknown): boolean => {
  if (!isRecord(value)) return false;
  return isString(value.q) && isString(value.answer);
};

const isMultipleChoiceQuestion = (value: unknown): boolean => {
  if (!isRecord(value)) return false;
  return isString(value.q) && isStringArray(value.choices) && isNumber(value.answer_index);
};

const isTrueFalseQuestion = (value: unknown): boolean => {
  if (!isRecord(value)) return false;
  return isString(value.q) && isBoolean(value.answer);
};

const isShortLongAnswerQuestion = (value: unknown): boolean => {
  if (!isRecord(value)) return false;
  return isString(value.q) && isString(value.ideal_answer) && isString(value.grading_criteria);
};

export const questionTypeRegistry: QuestionTypeRegistryEntry[] = [
  {
    enabledToggleKey: "matchingEnabled",
    quantityKey: "matchingQuantity",
    description: "Matching (pair terms with definitions)",
    schemaShape: "{ \"prompt\": string, \"pairs\": [ { \"left\": string, \"right\": string } ], \"explanation\": string }",
    typeGuard: isMatchingQuestion
  },
  {
    enabledToggleKey: "selectAllEnabled",
    quantityKey: "selectAllQuantity",
    description: "Select All (multiple correct choices)",
    schemaShape: "{ \"q\": string, \"choices\": string[], \"correct_indexes\": number[], \"explanation\": string }",
    typeGuard: isSelectAllQuestion
  },
  {
    enabledToggleKey: "fillBlankEnabled",
    quantityKey: "fillBlankQuantity",
    description: "Fill in the Blank (short text answer)",
    schemaShape: "{ \"q\": string, \"answer\": string, \"explanation\": string }",
    typeGuard: isFillBlankQuestion
  },
  {
    enabledToggleKey: "multipleChoiceEnabled",
    quantityKey: "multipleChoiceQuantity",
    description: "Multiple Choice (single correct choice)",
    schemaShape: "{ \"q\": string, \"choices\": string[], \"answer_index\": number, \"explanation\": string }",
    typeGuard: isMultipleChoiceQuestion
  },
  {
    enabledToggleKey: "trueFalseEnabled",
    quantityKey: "trueFalseQuantity",
    description: "True/False",
    schemaShape: "{ \"q\": string, \"answer\": boolean, \"explanation\": string }",
    typeGuard: isTrueFalseQuestion
  },
  {
    enabledToggleKey: "shortLongEnabled",
    quantityKey: "shortLongQuantity",
    description: "Short/Long Answer (graded response)",
    schemaShape: "{ \"q\": string, \"ideal_answer\": string, \"grading_criteria\": string, \"explanation\": string }",
    typeGuard: isShortLongAnswerQuestion
  }
];

export const DEFAULT_QUESTION_TYPE_SETTINGS: QuestionTypeSettings = {
  matchingEnabled: false,
  matchingQuantity: 0,
  selectAllEnabled: false,
  selectAllQuantity: 0,
  fillBlankEnabled: false,
  fillBlankQuantity: 0,
  multipleChoiceEnabled: true,
  multipleChoiceQuantity: 10,
  trueFalseEnabled: false,
  trueFalseQuantity: 0,
  shortLongEnabled: false,
  shortLongQuantity: 0
};
