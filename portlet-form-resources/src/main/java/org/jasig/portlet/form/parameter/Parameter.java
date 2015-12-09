/**
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.portlet.form.parameter;

/**
 * 
 * @author Jen Bourey, jennifer.bourey@gmail.com
 * @version $Revision$
 */
public class Parameter {

    private String name;
    private boolean readOnly;
    private String labelKey;
    private String descriptionKey;
    private String example;
    private ParameterInput input;

    /**
     * Get the name of this form parameter.  This is the value that will
     * be used to submit the value inside the form. 
     * 
     * @return name of this form parameter
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of this form paramter.  This is the value that will be 
     * used to submit the value inside the form.
     * 
     * @param name name of this form parameter
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Determine if this parameter is read-only.
     * 
     * @return True if this parameter is read-only
     */
    public boolean getReadOnly() {
        return readOnly;
    }

    /**
     * Set whether this parameter should be considered read-only.
     * @param readOnly True to indicate this parameter is read-only
     */
    public void setReadOnly(boolean readOnly) {
        this.readOnly = readOnly;
    }

    /**
     * Get the key of the message to be used as the parameter label. 
     * 
     * @return key of the message to be used as the parameter label
     */
    public String getLabelKey() {
        return labelKey;
    }

    /**
     * Set the key of the message to be used as the parameter label.
     * 
     * @param labelKey key of the message to be used as the parameter label
     */
    public void setLabelKey(String labelKey) {
        this.labelKey = labelKey;
    }

    /**
     * Get the key of the message to be used as the parameter description 
     * (optional).
     * 
     * @return key of the message to be used as the parameter description
     */
    public String getDescriptionKey() {
        return descriptionKey;
    }

    /**
     * Set the key of the message to be used as the parameter description 
     * (optional).
     * 
     * @param descriptionKey key of the message to be used as the parameter description
     */
    public void setDescriptionKey(String descriptionKey) {
        this.descriptionKey = descriptionKey;
    }

    /**
     * Get an example valid value for this parameter (optional).
     * 
     * @return example valid value for this parameter
     */
    public String getExample() {
        return example;
    }

    /**
     * Set an example valid value for this parameter (optional).
     * 
     * @param example example valid value for this parameter
     */
    public void setExample(String example) {
        this.example = example;
    }

    /**
     * Get the input type object to be used to construct form field(s) for this parameter.
     * 
     * @return input type object to be used to construct form field(s) for this parameter
     */
    public ParameterInput getInput() {
        return input;
    }

    /**
     * Set the input type object to be used to construct form field(s) for this parameter.
     * 
     * @param input input type object to be used to construct form field(s) for this parameter
     */
    public void setInput(ParameterInput input) {
        this.input = input;
    }

}
