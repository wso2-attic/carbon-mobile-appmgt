/*
 * Copyright WSO2 Inc.
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

package org.wso2.carbon.appmgt.impl.template;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.exception.ParseErrorException;
import org.apache.velocity.exception.ResourceNotFoundException;
import org.wso2.carbon.appmgt.impl.AppMConstants;
import org.wso2.carbon.appmgt.impl.AppManagerConfigurationService;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Constructs WebApp and resource configurations for the ESB/Synapse using a Apache velocity
 * templates.
 */
public class APITemplateBuilderImpl {

	private static final Log log = LogFactory.getLog(APITemplateBuilderImpl.class);

	private static final String VELOCITY_TEMPLATE_SYNAPSE_CONFIG_NON_VERSIONED_WEBAPP =
			"velocity-template_synapse-config_non-versioned-webapp.xml";
	private static final String VELOCITY_TEMPLATE_SYNAPSE_CONFIG_VERSIONED_WEBAPP =
			"velocity-template_synapse-config_versioned-webapp.xml";

	private String velocityLoggerName = null;
	private List<HandlerConfig> handlers = new ArrayList<HandlerConfig>();

	public void addHandler(String handlerName, Map<String, String> properties) {
		addHandlerPriority(handlerName, properties, handlers.size());
	}

	public void addHandlerPriority(String handlerName, Map<String, String> properties,
								   int priority) {
		HandlerConfig handler = new HandlerConfig(handlerName, properties);
		handlers.add(priority, handler);
	}

	private String getVersionedWebAppTemplatePath() {
		return "repository" + File.separator + "resources" + File.separator + "api_templates" +
				File.separator +
				APITemplateBuilderImpl.VELOCITY_TEMPLATE_SYNAPSE_CONFIG_VERSIONED_WEBAPP;
	}

	private String getNonVersionedWebAppTemplatePath() {
		return "repository" + File.separator + "resources" + File.separator + "api_templates" +
				File.separator +
				APITemplateBuilderImpl.VELOCITY_TEMPLATE_SYNAPSE_CONFIG_NON_VERSIONED_WEBAPP;
	}

	private String getVelocityLoggerName() {
		AppManagerConfigurationService config =
				ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService();
		String velocityLogPath = config.getAPIManagerConfiguration().getFirstProperty(
				AppMConstants.VELOCITY_LOGGER);
		if (velocityLogPath != null && velocityLogPath.length() > 1) {
			return velocityLogPath;
		} else {
			return null;
		}
	}

	private String processTemplate(VelocityEngine ve, VelocityContext vc, String templatePath)
			throws APITemplateException {
		StringWriter writer = new StringWriter();
		try {
			Template t = ve.getTemplate(templatePath);
			t.merge(vc, writer);
		} catch (ResourceNotFoundException e) {
			String msg = "Cannot find Velocity template " + templatePath;
			log.error(msg, e);
			throw new APITemplateException(msg, e);
		} catch (ParseErrorException e) {
			String msg = "Cannot parse Velocity template " + templatePath;
			log.error(msg, e);
			throw new APITemplateException(msg, e);
		} catch (IOException e) {
			log.error("Cannot write processed Velocity template", e);
			throw new APITemplateException("Cannot write processed Velocity template", e);
		} catch (Exception e) {
			log.error("Cannot process Velocity template", e);
			throw new APITemplateException("Cannot process Velocity template", e);
		}
		return writer.toString();
	}
}
