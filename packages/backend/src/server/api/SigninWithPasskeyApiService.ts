/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { randomUUID } from 'crypto';
import { Inject, Injectable } from '@nestjs/common';
import { IsNull } from 'typeorm';
import { DI } from '@/di-symbols.js';
import type {
	SigninsRepository,
	UserProfilesRepository,
	UsersRepository,
} from '@/models/_.js';
import type { Config } from '@/config.js';
import { getIpHash } from '@/misc/get-ip-hash.js';
import type { MiLocalUser, MiUser } from '@/models/User.js';
import { IdService } from '@/core/IdService.js';
import { bindThis } from '@/decorators.js';
import { WebAuthnService } from '@/core/WebAuthnService.js';
import Logger from '@/logger.js';
import { LoggerService } from '@/core/LoggerService.js';
import type { IdentifiableError } from '@/misc/identifiable-error.js';
import { RateLimiterService } from './RateLimiterService.js';
import { SigninService } from './SigninService.js';
import type { AuthenticationResponseJSON } from '@simplewebauthn/types';
import type { FastifyReply, FastifyRequest } from 'fastify';

@Injectable()
export class SigninWithPasskeyApiService {
	private logger: Logger;
	constructor(
		@Inject(DI.config)
		private config: Config,

		@Inject(DI.usersRepository)
		private usersRepository: UsersRepository,

		@Inject(DI.userProfilesRepository)
		private userProfilesRepository: UserProfilesRepository,

		@Inject(DI.signinsRepository)
		private signinsRepository: SigninsRepository,

		private idService: IdService,
		private rateLimiterService: RateLimiterService,
		private signinService: SigninService,
		private webAuthnService: WebAuthnService,
		private loggerService: LoggerService,
	) {
		this.logger = this.loggerService.getLogger('PasskeyAuth');
	}

	@bindThis
	public async signin(
		request: FastifyRequest<{
			Body: {
				credential?: AuthenticationResponseJSON;
				context?: string;
			};
		}>,
		reply: FastifyReply,
	) {
		reply.header('Access-Control-Allow-Origin', this.config.url);
		reply.header('Access-Control-Allow-Credentials', 'true');

		const body = request.body;
		const credential = body['credential'];

		function error(status: number, error: { id: string }) {
			reply.code(status);
			return { error };
		}

		const fail = async (userId: MiUser['id'], status?: number, failure?: { id: string }) => {
			// 记录登录历史
			await this.signinsRepository.insert({
				id: this.idService.gen(),
				userId: userId,
				ip: request.ip,
				headers: request.headers as any,
				success: false,
			});
			return error(status ?? 500, failure ?? { id: '4e30e80c-e338-45a0-8c8f-44455efa3b76' });
		};

		try {
			// 每250毫秒不超过1次API调用，每30分钟不超过100次尝试
			// 注意：1次登录需要2次API调用
			await this.rateLimiterService.limit({ key: 'signin-with-passkey', duration: 60 * 30 * 1000, max: 200, minInterval: 250 }, getIpHash(request.ip));
		} catch (err) {
			reply.code(429);
			return {
				error: {
					message: 'Too many failed attempts to sign in. Try again later.',
					code: 'TOO_MANY_AUTHENTICATION_FAILURES',
					id: '22d05606-fbcf-421a-a2db-b32610dcfd1b',
				},
			};
		}

		// 使用上下文初始化密钥认证挑战
		if (!credential) {
			const context = randomUUID();
			this.logger.info(`Initiate Passkey challenge: context: ${context}`);
			const authChallengeOptions = {
				option: await this.webAuthnService.initiateSignInWithPasskeyAuthentication(context),
				context: context,
			};
			reply.code(200);
			return authChallengeOptions;
		}

		const context = body.context;
		if (!context || typeof context !== 'string') {
			// 如果在没有上下文的情况下尝试认证
			return error(400, {
				id: '1658cc2e-4495-461f-aee4-d403cdf073c1',
			});
		}

		this.logger.debug(`尝试使用密钥登录：上下文：${context}`);

		let authorizedUserId: MiUser['id'] | null;
		try {
			authorizedUserId = await this.webAuthnService.verifySignInWithPasskeyAuthentication(context, credential);
		} catch (err) {
			this.logger.warn(`密钥认证验证错误！：${err}`);
			const errorId = (err as IdentifiableError).id;
			return error(403, {
				id: errorId,
			});
		}

		if (!authorizedUserId) {
			return error(403, {
				id: '932c904e-9460-45b7-9ce6-7ed33be7eb2c',
			});
		}

		const user = await this.usersRepository.findOneBy({
			id: authorizedUserId,
			host: IsNull(),
		}) as MiLocalUser | null;

		if (user == null) {
			return error(403, {
				id: '652f899f-66d4-490e-993e-6606c8ec04c3',
			});
		}

		if (user.isSuspended) {
			return error(403, {
				id: 'e03a5f46-d309-4865-9b69-56282d94e1eb',
			});
		}

		const profile = await this.userProfilesRepository.findOneByOrFail({ userId: user.id });

		// 认证成功，但未启用无密码登录
		if (!profile.usePasswordLessLogin) {
			return await fail(user.id, 403, {
				id: '2d84773e-f7b7-4d0b-8f72-bb69b584c912',
			});
		}

		const signinResponse = this.signinService.signin(request, reply, user);
		return {
			signinResponse: signinResponse,
		};
	}
}
