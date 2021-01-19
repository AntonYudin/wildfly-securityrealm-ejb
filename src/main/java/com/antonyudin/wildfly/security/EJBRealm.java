
/*
 * vim: set nowrap:
 */
 
/*
 * Copyright 2018 Anton Yudin
 *
 * mailto:dev@antonyudin.com
 * https://antonyudin.com/software
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.antonyudin.wildfly.security;


import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;

import java.util.concurrent.ConcurrentHashMap;

import org.wildfly.extension.elytron.Configurable;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.AuthorizationIdentity;


public class EJBRealm implements SecurityRealm, Configurable {

	private final static java.util.logging.Logger logger = java.util.logging.Logger.getLogger(
		EJBRealm.class.getName()
	);


	private final String ejbPathName = "ejbPath";
	private final List<String> ejbPaths = new ArrayList<>();

	private final Map<String, Attributes> cache = new ConcurrentHashMap<>();


	@Override
	public void initialize(final Map<String, String> configuration) {

		logger.fine(() -> "initialize(" + configuration + ")");

		{
			final String value = configuration.get(ejbPathName);

			if (value != null)
				ejbPaths.add(value);
		}

		for (int i = 0;; i++) {
			final String value = configuration.get(ejbPathName + "." + i);
			if (value != null)
				ejbPaths.add(value);
			else
				break;
		}

		logger.fine(() -> "ejbPaths: [" + ejbPaths + "]");
	}


	@Override
	public SupportLevel getCredentialAcquireSupport(
		final Class<? extends Credential> credentialType,
		final String algorithmName,
		final AlgorithmParameterSpec parameterSpec
	) throws RealmUnavailableException {
		logger.fine(
			() ->
			"getCredentialAcquireSupport(" +
			credentialType + ", " +
			algorithmName + ", " +
			parameterSpec + ")"
		);
		return SupportLevel.UNSUPPORTED;
	}


	@Override
	public SupportLevel getEvidenceVerifySupport(
		final Class<? extends Evidence> evidenceType,
		final String algorithmName
	) throws RealmUnavailableException {

		logger.fine(
			() ->
			"getEvidenceVerifySupport(" +
			evidenceType + ", " +
			algorithmName + ")"
		);

		return (
			PasswordGuessEvidence.class.isAssignableFrom(evidenceType)?
			SupportLevel.POSSIBLY_SUPPORTED:
			SupportLevel.UNSUPPORTED
		);
	}


	protected Map<String, Object> authenticate(final String name, final String password) {

		logger.fine(() -> "\tusing ejbPaths: [" + ejbPaths + "]");

		for (String ejbPath: ejbPaths) {
			try {
				final javax.naming.Context context = new javax.naming.InitialContext();

				final Object bean = context.lookup(ejbPath);

				logger.fine(() -> "name: [" + name + "]");

				final java.lang.reflect.Method method = bean.getClass().getMethod(
					"authenticate", String.class, String.class
				);

				logger.fine(() -> "found method: [" + method + "]");

				@SuppressWarnings("unchecked")
				final Map<String, Object> result = (Map<String, Object>) method.invoke(
					bean, name, password
				);

				logger.fine(() -> "result: [" + result + "]");

				if (result != null)
					return result;

			} catch (java.lang.Exception exception) {

				logger.log(java.util.logging.Level.SEVERE, "error authenticating", exception);
			}
		}

		return null;
	}


	@Override
	public RealmIdentity getRealmIdentity(final Evidence evidence) throws RealmUnavailableException {
		logger.fine(() -> "getRealmIdentity(" + evidence + ")");
		return SecurityRealm.super.getRealmIdentity(evidence);
	}


	@Override
	public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {

		logger.fine(() -> "getRealmIdentity: [" + principal + ", " + principal.getName() + "]");

		return new RealmIdentity() {

			@Override
			public Principal getRealmIdentityPrincipal() {
				logger.fine(() -> "getRealmIdentityPrincipal()");
				return principal;
    			}


			@Override
			public SupportLevel getCredentialAcquireSupport(
				final Class<? extends Credential> credentialType,
				final String algorithmName,
				final AlgorithmParameterSpec parameterSpec
			) throws RealmUnavailableException {
				logger.fine(
					() ->
					"getCredentialAcquireSupport(" +
					credentialType + ", " + algorithmName + ", " +
					parameterSpec + ")"
				);
				return SupportLevel.UNSUPPORTED;
			}


			@Override
			public <C extends Credential> C getCredential(
				final Class<C> credentialType
			) throws RealmUnavailableException {
				logger.fine(() -> "getCredential(" + credentialType + ")");
				return null;
			}


			@Override
			public SupportLevel getEvidenceVerifySupport(
				final Class<? extends Evidence> evidenceType,
				final String algorithmName
			) throws RealmUnavailableException {

				logger.fine(() -> "getEvidenceVerifySupport(" + evidenceType + ", " + algorithmName + ")");

				return (
					PasswordGuessEvidence.class.isAssignableFrom(evidenceType)?
					SupportLevel.SUPPORTED:
					SupportLevel.UNSUPPORTED
				);
			}	


			@Override
			public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {

				logger.fine(() -> "verifyEvidence(" + evidence + ")");

				if (evidence instanceof PasswordGuessEvidence) {

					final PasswordGuessEvidence guess = (PasswordGuessEvidence) evidence;

					logger.fine(() -> "guess: [" + guess.getGuess() + "]");

					try {
						final String principal = getRealmIdentityPrincipal().getName();

						final Map<String, Object> result = authenticate(
							principal,
							new String(guess.getGuess())
						);

						if (result != null) {

							final MapAttributes attributes = new MapAttributes();

							for (final Map.Entry<String, Object> entry: result.entrySet()) {

								if (entry.getValue() == null)
									continue;

								if (entry.getValue() instanceof String[]) {

									final String[] values = (String[]) entry.getValue();

									for (int i = 0; i < values.length; i++) {

										final String value = values[i];

										attributes.add(entry.getKey(), i, value);

										logger.fine(() -> "\tsetting [" + entry.getKey() + "]: [" + value + "]");
									}

								} else {
									attributes.add(entry.getKey(), 0, entry.getValue().toString());
									logger.fine(() -> "\tsetting [" + entry.getKey() + "] (0): [" + entry.getValue().toString() + "]");
								}
							}

							cache.put(principal, attributes);

							return true;
						}

					} finally {
						guess.destroy();
					}
				}

				return false;
			}


			@Override
			public boolean exists() throws RealmUnavailableException {
				logger.fine(() -> "exists()");
				return true;
			}


			@Override
			public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
				logger.fine(() -> "getAuthorizationIdentity()");

				final Attributes attributes = getAttributes();

				return new AuthorizationIdentity() {
					@Override
					public Attributes getAttributes() {
						logger.fine(() -> "getAttributes(): " + attributes);
						return attributes;
					}
				};
			}

			@Override
			public Attributes getAttributes() throws RealmUnavailableException {

				logger.fine(() -> "getAttributes()");

				final String principal = getRealmIdentityPrincipal().getName();

				logger.fine(() -> "\tusing principal [" + principal + "]");

				return cache.get(principal);
			}
		};
	}

}

