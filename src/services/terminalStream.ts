export function decodeTerminalPayload(dataBase64: string) {
  const binary = globalThis.atob(dataBase64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function updateTrackedTerminalLine(current: string, data: string) {
  let line = current;
  for (const character of data) {
    if (character === "\r" || character === "\n" || character === "\u0003") line = "";
    else if (character === "\u007f" || character === "\b") line = line.slice(0, -1);
    else if (character === "\u001b") return "";
    else if (character === "\t") continue;
    else if (character >= " ") line += character;
  }
  return line;
}

export function isWpCliTerminalLine(line: string) {
  return /^wp(?:\s|$)/.test(line.trimStart());
}

export function completionKeystrokes(current: string, completed: string) {
  let shared = 0;
  const currentCharacters = [...current];
  const completedCharacters = [...completed];
  while (shared < currentCharacters.length && shared < completedCharacters.length && currentCharacters[shared] === completedCharacters[shared]) shared += 1;
  return "\u007f".repeat(currentCharacters.length - shared) + completedCharacters.slice(shared).join("");
}
