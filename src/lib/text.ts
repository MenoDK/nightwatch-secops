// biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the whole point
const CONTROL = /[\u0000-\u001f\u007f]/g;

/**
 * Text from outside - a log line, an account name, a model's explanation - ends up in logs, tables and a web page.
 * Control characters are how a line pretends to be two lines or hides a terminal escape sequence, so they go.
 */
export const stripControl = (text: string, replacement = ' '): string => text.replace(CONTROL, replacement);
