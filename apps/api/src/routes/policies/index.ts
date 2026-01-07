import { Router } from 'express';

import { policySetsRouter } from './policy-sets.js';
import { policyVersionsRouter } from './policy-versions.js';
import { policyRulesRouter } from './policy-rules.js';
import { policyRenderRouter } from './render.js';

export const policiesRouter = Router();

policiesRouter.use('/policy-sets', policySetsRouter);
policiesRouter.use('/', policyVersionsRouter);
policiesRouter.use('/', policyRulesRouter);
policiesRouter.use('/', policyRenderRouter);


