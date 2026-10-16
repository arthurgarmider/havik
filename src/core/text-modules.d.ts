// Rule files are built into the program as text (import … with { type: 'text' }).
declare module '*.yaml' {
  const text: string
  export default text
}
