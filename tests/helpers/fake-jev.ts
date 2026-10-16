// A local stand-in for the TypeSafe API, so --ai can be tested end to end without a key or a network.
export interface JevRequest { readonly state: any; readonly questions: Record<string, { type: string; instructions: string }>; readonly model: string }
export interface FakeJev { readonly url: string; readonly requests: JevRequest[]; stop(): void }

// `respond` returns the probability to answer every question with, or a ready-made Response (to simulate a failure).
export function startFakeJev(respond: (request: JevRequest, count: number) => number | Response = () => 0): FakeJev {
  const requests: JevRequest[] = []
  const server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    fetch: async (req) => {
      const body = (await req.json()) as JevRequest
      requests.push(body)
      const result = respond(body, requests.length)
      if (result instanceof Response) return result
      const answers = Object.fromEntries(Object.keys(body.questions).map((q) => [q, { type: 'noul', noul: result }]))
      return Response.json({ model: 'jev-test', answers, usage: { input_tokens: 1, output_tokens: 1 } })
    },
  })
  return { url: `http://127.0.0.1:${server.port}`, requests, stop: () => server.stop(true) }
}
