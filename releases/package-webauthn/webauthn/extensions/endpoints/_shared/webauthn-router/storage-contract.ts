export type FieldSpec = {
  field: string;
  type: 'string' | 'text' | 'integer' | 'uuid' | 'json' | 'boolean' | 'timestamp';
  schema: {
    is_nullable?: boolean;
    is_unique?: boolean;
    default_value?: any;
  };
  meta?: {
    interface?: string | null;
    special?: string[];
    hidden?: boolean;
    readonly?: boolean;
    note?: string | null;
    options?: Record<string, any> | null;
  };
};

export const CREDENTIALS_COLLECTION = 'webauthn_credentials';
export const CHALLENGES_COLLECTION = 'webauthn_challenges';

export const requiredCredentialsFields: FieldSpec[] = [
  {
    field: 'user',
    type: 'uuid',
    schema: { is_nullable: false },
    meta: { interface: 'select-dropdown-m2o', special: ['m2o'], readonly: false, hidden: false },
  },
  {
    field: 'credential_id',
    type: 'string',
    schema: { is_nullable: false, is_unique: true },
    meta: { interface: 'input', readonly: false, hidden: false },
  },
  {
    field: 'public_key',
    type: 'text',
    schema: { is_nullable: false },
    meta: { interface: 'input', readonly: false, hidden: false },
  },
  {
    field: 'sign_count',
    type: 'integer',
    schema: { is_nullable: false, default_value: 0 },
    meta: { interface: 'input', readonly: false, hidden: false },
  },
];

export const requiredChallengesFields: FieldSpec[] = [
  { field: 'type', type: 'string', schema: { is_nullable: false }, meta: { interface: 'input', hidden: false } },
  {
    field: 'challenge_id',
    type: 'string',
    schema: { is_nullable: false, is_unique: true },
    meta: { interface: 'input', hidden: false },
  },
  {
    field: 'challenge',
    type: 'json',
    schema: { is_nullable: false },
    meta: { interface: 'json', hidden: false },
  },
  { field: 'expires_at', type: 'timestamp', schema: { is_nullable: false }, meta: { interface: 'datetime', hidden: false } },
];

export const credentialsFieldNames = requiredCredentialsFields.map((f) => f.field);
export const challengesFieldNames = requiredChallengesFields.map((f) => f.field);

export type StorageContract = {
  collections: { credentials: string; challenges: string };
  credentials: FieldSpec[];
  challenges: FieldSpec[];
};

export const STORAGE_CONTRACT: StorageContract = {
  collections: { credentials: CREDENTIALS_COLLECTION, challenges: CHALLENGES_COLLECTION },
  credentials: requiredCredentialsFields,
  challenges: requiredChallengesFields,
};
