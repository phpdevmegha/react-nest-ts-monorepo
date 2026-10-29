import 'dotenv/config';
import * as bcrypt from 'bcrypt';
import { AppDataSource } from './datasource/config';
import { UserRole } from '../users/dto/create-user.dto';
import { User } from '../users/entities/user.entity';

interface SeedOptions {
  name: string;
  email: string;
  password: string;
  role: UserRole;
}

const BCRYPT_ROUNDS = 8;

function readArg(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  return index !== -1 ? process.argv[index + 1] : undefined;
}

function parseRole(value: string | undefined): UserRole {
  const role = (value ?? process.env.SEED_ADMIN_ROLE ?? UserRole.ADMIN).toUpperCase();

  if (!Object.values(UserRole).includes(role as UserRole)) {
    throw new Error(
      `Invalid role "${value}". Use one of: ${Object.values(UserRole).join(', ')}`,
    );
  }

  return role as UserRole;
}

function readOptions(): SeedOptions {
  return {
    name: readArg('--name') ?? process.env.SEED_ADMIN_NAME ?? 'Admin',
    email: (
      readArg('--email') ??
      process.env.SEED_ADMIN_EMAIL ??
      'admin@syncboard.dev'
    ).toLowerCase(),
    password:
      readArg('--password') ??
      process.env.SEED_ADMIN_PASSWORD ??
      'password123',
    role: parseRole(readArg('--role') ?? process.env.SEED_ADMIN_ROLE),
  };
}

async function seed(): Promise<void> {
  const options = readOptions();

  if (options.password.length < 6) {
    throw new Error('Password must be at least 6 characters long.');
  }

  await AppDataSource.initialize();

  try {
    const repository = AppDataSource.getRepository(User);
    const password = await bcrypt.hash(options.password, BCRYPT_ROUNDS);
    const existing = await repository.findOne({
      where: { email: options.email },
    });

    if (existing) {
      existing.name = options.name;
      existing.password = password;
      existing.role = options.role;
      await repository.save(existing);

      console.log(
        `Updated user ${existing.email} (id=${existing.id}, role=${existing.role})`,
      );
    } else {
      const user = repository.create({ ...options, password });
      await repository.save(user);

      console.log(`Created user ${user.email} (id=${user.id}, role=${user.role})`);
    }

    console.log(`Login with: ${options.email} / ${options.password}`);
  } finally {
    await AppDataSource.destroy();
  }
}

seed().catch((error: unknown) => {
  console.error(
    'Seed failed:',
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
