/** The `Cookie` header a browser sends back after `response`: every cookie it was given, without attributes. */
export const cookiesOf = (response: Response): string =>
  response.headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .join("; ");
