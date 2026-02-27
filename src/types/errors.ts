export class ValidationError extends Error {
  public status: number;
  public details: any[];

  constructor(details: any[]) {
    super("Validation Error");
    this.name = "ValidationError";
    this.status = 400;
    this.details = details;
  }
}

export class AppError extends Error {
  public status: number;
  public code: string;

  constructor(message: string, status: number = 500, code: string = 'INTERNAL_SERVER_ERROR') {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
  }
}
