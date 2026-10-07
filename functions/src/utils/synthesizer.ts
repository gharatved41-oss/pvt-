import { faker } from '@faker-js/faker';

// =============================================================================
// SYNTHETIC DATA SYNTHESIZER FOR DIGITAL TWIN SANDBOX
// =============================================================================

export interface SyntheticUserRecord {
  id: string;
  fullName: string;
  email: string;
  passwordHash: string;
  syntheticCreditCard: {
    number: string;
    exp: string;
    cvv: string;
  };
  role: 'admin' | 'finance' | 'customer' | 'employee';
  createdAt: string;
}

export interface SyntheticLogRecord {
  id: string;
  timestamp: string;
  clientIp: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  endpoint: string;
  statusCode: number;
  userAgent: string;
  responseTimeMs: number;
}

export type SyntheticSchemaType = 'users' | 'logs';

/**
 * generateSyntheticPayload
 * Intercepts cloud clone operations to synthesize 100% fake, compliant data
 * mimicking production schemas without exposing PII or regulated secrets.
 */
export function generateSyntheticPayload(
  schemaType: SyntheticSchemaType, 
  count: number = 1000
): SyntheticUserRecord[] | SyntheticLogRecord[] {
  if (schemaType === 'users') {
    const users: SyntheticUserRecord[] = [];
    for (let i = 0; i < count; i++) {
      const firstName = faker.person.firstName();
      const lastName = faker.person.lastName();
      users.push({
        id: faker.string.uuid(),
        fullName: `${firstName} ${lastName}`,
        email: faker.internet.email({ firstName, lastName }).toLowerCase(),
        passwordHash: `$2b$12$${faker.string.alphanumeric(53)}`, // Realistic bcrypt digest
        syntheticCreditCard: {
          number: faker.finance.creditCardNumber({ issuer: 'visa' }),
          exp: `${faker.number.int({ min: 1, max: 12 }).toString().padStart(2, '0')}/${faker.number.int({ min: 27, max: 32 })}`,
          cvv: faker.finance.creditCardCVV(),
        },
        role: faker.helpers.arrayElement(['admin', 'finance', 'customer', 'employee']),
        createdAt: faker.date.past({ years: 2 }).toISOString(),
      });
    }
    return users;
  }

  if (schemaType === 'logs') {
    const logs: SyntheticLogRecord[] = [];
    const endpoints = [
      '/api/v1/auth/login',
      '/api/v1/users/me',
      '/api/v1/billing/charge',
      '/api/v1/transactions',
      '/admin/metrics',
      '/healthz'
    ];
    const methods: Array<'GET' | 'POST' | 'PUT' | 'DELETE'> = ['GET', 'POST', 'PUT', 'DELETE'];
    const statusCodes = [200, 200, 200, 201, 204, 400, 401, 403, 404, 500];

    for (let i = 0; i < count; i++) {
      logs.push({
        id: faker.string.uuid(),
        timestamp: faker.date.recent({ days: 7 }).toISOString(),
        clientIp: faker.internet.ip(),
        method: faker.helpers.arrayElement(methods),
        endpoint: faker.helpers.arrayElement(endpoints),
        statusCode: faker.helpers.arrayElement(statusCodes),
        userAgent: faker.internet.userAgent(),
        responseTimeMs: faker.number.int({ min: 12, max: 840 }),
      });
    }
    return logs;
  }

  throw new Error(`Unsupported synthetic schemaType: ${schemaType}`);
}
