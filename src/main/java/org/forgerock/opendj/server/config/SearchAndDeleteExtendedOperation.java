/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2016-2017 ForgeRock AS.
 */
package org.forgerock.opendj.server.config;

import static org.forgerock.opendj.server.config.ExamplePluginMessages.*;
import static org.opends.server.util.StaticUtils.getExceptionMessage;

import java.io.IOException;
import org.forgerock.i18n.LocalizableMessage;

import org.forgerock.i18n.slf4j.LocalizedLogger;
import org.forgerock.opendj.io.Asn1;
import org.forgerock.opendj.io.Asn1Reader;
import org.forgerock.opendj.io.Asn1Writer;
import org.forgerock.opendj.ldap.ByteString;
import org.forgerock.opendj.ldap.ByteStringBuilder;
import org.forgerock.opendj.ldap.ResultCode;
import org.forgerock.opendj.ldap.SearchResultHandler;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.messages.Requests;
import org.forgerock.opendj.ldap.messages.Result;
import org.forgerock.opendj.ldap.messages.SearchRequest;
import org.forgerock.opendj.ldap.messages.SearchResultEntry;
import org.forgerock.opendj.ldap.messages.SearchResultReference;
import org.forgerock.opendj.server.config.server.SearchAndDeleteExtendedOperationHandlerCfg;
import org.opends.server.api.ExtendedOperationHandler;
import org.opends.server.core.ExtendedOperation;
import org.opends.server.protocols.internal.InternalClientConnection;
import org.opends.server.types.AuthenticationInfo;

public class SearchAndDeleteExtendedOperation
        extends ExtendedOperationHandler<SearchAndDeleteExtendedOperationHandlerCfg> {

    public static final byte TYPE_SEARCH_BASE_ELEMENT = (byte) 0x80;
    public static final byte TYPE_SEARCH_FILTER_ELEMENT = (byte) 0x81;
    public static final byte TYPE_RESULT_COUNT_ELEMENT = (byte) 0x80;
    public static final String OID_SEARCH_AND_DELETE_REQUEST = "1.3.6.1.4.1.36733.2.1.999.1";

    private static final LocalizedLogger LOGGER = LocalizedLogger.getLoggerForThisClass();

    @Override
    public void processExtendedOperation(ExtendedOperation operation) {
        ByteString requestValue = operation.getRequestValue();
        if (requestValue == null) {
            operation.setResultCode(ResultCode.PROTOCOL_ERROR);
            operation.appendErrorMessage(ERR_MISSING_REQUEST_VALUE.get());
            return;
        }

        ByteString searchBase = null;
        ByteString searchFilter = null;
        try {
            Asn1Reader reader = Asn1.getReader(requestValue);
            reader.readStartSequence();
            if (reader.hasNextElement() && reader.peekType() == TYPE_SEARCH_BASE_ELEMENT) {
                searchBase = reader.readOctetString();
            }
            if (reader.hasNextElement() && reader.peekType() == TYPE_SEARCH_FILTER_ELEMENT) {
                searchFilter = reader.readOctetString();
            }
            reader.readEndSequence();
        } catch (IOException ioe) {
            LOGGER.traceException(ioe);
            operation.setResultCode(ResultCode.PROTOCOL_ERROR);
            operation.appendErrorMessage(ERR_PARSING_ERROR.get(getExceptionMessage(ioe)));
            return;
        }

        if (searchBase == null || searchBase.isEmpty()) {
            operation.setResultCode(ResultCode.PROTOCOL_ERROR);
            operation.appendErrorMessage(ERR_MISSING_SEARCH_BASE.get());
            return;
        } else if (searchFilter == null || searchFilter.isEmpty()) {
            operation.setResultCode(ResultCode.PROTOCOL_ERROR);
            operation.appendErrorMessage(ERR_MISSING_SEARCH_FILTER.get());
            return;
        }

        final AuthenticationInfo authenticationInfo = operation.getClientConnection().getAuthenticationInfo();
        if (!authenticationInfo.isAuthenticated()) {
            operation.setResultCode(ResultCode.UNWILLING_TO_PERFORM);
            operation.appendErrorMessage(ERR_UNAUTHENTICATED_REQUEST.get());
        }

        final InternalClientConnection connection = new InternalClientConnection(authenticationInfo);
        int matches = 0;
        while (true) {
            final SearchRequest searchRequest = Requests.newSearchRequest(searchBase.toString(),
                    SearchScope.WHOLE_SUBTREE, searchFilter.toString());
            searchRequest.addAttribute("1.1");
            searchRequest.setSizeLimit(500);
            Result results = connection.processSearch(searchRequest, new SearchResultHandler() {
                @Override
                public boolean handleEntry(SearchResultEntry entry) {
                    final Result result = connection.processDelete(Requests.newDeleteRequest(entry.getName()));
                    if (result.getResultCode().isExceptional()) {
                        LOGGER.warn(LocalizableMessage.valueOf(result.getDiagnosticMessage()));
                    }
                    return true;
                }

                @Override
                public boolean handleReference(SearchResultReference reference) {
                    return true;
                }
            });
            ResultCode resultCode = results.getResultCode();
            if (ResultCode.SUCCESS.equals(resultCode)) {
                break;
            } else if (!ResultCode.SIZE_LIMIT_EXCEEDED.equals(resultCode)) {
                operation.setResultCode(results.getResultCode());
                operation.appendErrorMessage(LocalizableMessage.valueOf(results.getDiagnosticMessage()));
                return;
            }
        }
        operation.setResultCode(ResultCode.SUCCESS);

        ByteStringBuilder builder = new ByteStringBuilder();
        Asn1Writer writer = Asn1.getWriter(builder);
        try {
            writer.writeStartSequence();
            writer.writeInteger(TYPE_RESULT_COUNT_ELEMENT, matches);
            writer.writeEndSequence();
        } catch (IOException e) {
            LOGGER.traceException(e);
        }
        operation.setResponseValue(builder.toByteString());
    }

    @Override
    public String getExtendedOperationOID() {
        return OID_SEARCH_AND_DELETE_REQUEST;
    }

    @Override
    public String getExtendedOperationName() {
        return "Search and Delete";
    }
}
