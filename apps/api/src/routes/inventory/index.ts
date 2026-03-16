import { Router } from 'express';

import { hostsRouter } from './hosts.js';
import { tagsRouter } from './tags.js';
import { vlansRouter } from './vlans.js';
import { interfacesRouter } from './interfaces.js';
import { tagRulesRouter } from './tag-rules.js';

export const inventoryRouter = Router();

inventoryRouter.use('/hosts', hostsRouter);
inventoryRouter.use('/tags', tagsRouter);
inventoryRouter.use('/vlans', vlansRouter);
inventoryRouter.use('/tag-rules', tagRulesRouter);
inventoryRouter.use('/', interfacesRouter);



