/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }

    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');

    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }

*/

/*
 * This JS file has been modified to include temporal and environmental scores in the CVSS calculation.
 * Calculation is done through the use of first.org JS: https://www.first.org/cvss/calculator/cvsscalc31.js
 * 
 * Sergio García Spínola
 * 24/09/2020
*/

const CVSS = function (id, options, showGroups) {

    this.options = options;

    // Base Group
    baseGroup = {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        PR: 'Privileges Required',
        UI: 'User Interaction',
        S: 'Scope',
        C: 'Confidentiality',
        I: 'Integrity',
        A: 'Availability'        
    };

    // Temporal Group
    tempGroup = {
        //...baseGroup,
        E: 'Exploit Code Maturity',
        RL: 'Remediation Level',
        RC: 'Report Confidence',
    };

    // Environmental Group
    envGroup = {
        //...tempGroup,
        CR: 'Confidentiality Requirement',
        IR: 'Integrity Requirement',
        AR: 'Availability Requirement',        
        MAV: 'Modified Attack Vector',
        MAC: 'Modified Attack Complexity',        
        MPR: 'Modified Privileges Required',
        MUI: 'Modified User Interaction',
        MS: 'Modified Scope',
        MC: 'Modified Confidentiality',
        MI: 'Modified Integrity',
        MA: 'Modified Availability'
    };

    // All Groups
    allGroup = {
        base: {
            ...baseGroup
        },
        temp: {
            ...tempGroup
        },
        env: {
            ...envGroup
        }
    }

    // Base Metrics
    baseMetrics = {
        AV: {
            N: {
                l: 'Network',
                d: "<b>Worst:</b> The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers)."
            },
            A: {
                l: 'Adjacent',
                d: "<b>Worse:</b> The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment."
            },
            L: {
                l: 'Local',
                d: "<b>Bad:</b> The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: <ul><li>the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH);</li><li>or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).</li></ul>"
            },
            P: {
                l: 'Physical',
                d: "<b>Bad:</b> The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA)."
            }
        },
        AC: {
            L: {
                l: 'Low',
                d: "<b>Worst:</b> Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component."
            },
            H: {
                l: 'High',
                d: "<b>Bad:</b> A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected."
            }
        },
        PR: {
            N: {
                l: 'None',
                d: "<b>Worst:</b> The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack."
            },
            L: {
                l: 'Low',
                d: "<b>Worse</b> The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources."
            },
            H: {
                l: 'High',
                d: "<b>Bad:</b> The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
            }
        },
        UI: {
            N: {
                l: 'None',
                d: "<b>Worst:</b> The vulnerable system can be exploited without interaction from any user."
            },
            R: {
                l: 'Required',
                d: "<b>Bad:</b> Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator."
            }
        },

        S: {
            C: {
                l: 'Changed',
                d: "<b>Worst:</b> An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities."
            },
            U: {
                l: 'Unchanged',
                d: "<b>Bad:</b> An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority."
            }
        },
        C: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no loss of confidentiality within the impacted component."
            }
        },
        I: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no loss of integrity within the impacted component."
            }
        },
        A: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no impact to availability within the impacted component."
            }
        },
    };

    // Temporal Metrics
    tempMetrics = {
        //...baseMetrics,
        E: {
            X: {
                l: 'Not Defined',
                d: "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning High."
            },
            U: {
                l: 'Unproven',
                d: "No exploit code is available, or an exploit is theoretical."                
            },
            P: {
                l: 'Proof-of-Concept',
                d: "Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker."
            },
            F: {
                l: 'Functional',
                d: "Functional exploit code is available. The code works in most situations where the vulnerability exists."
            },
            H: {
                l: 'High',
                d: "Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely-available, easy-to-use automated tools."
            }
        },
        RL: {
            X: {
                l: 'Not Defined',
                d: "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning Unavailable."
            },
            O: {
                l: 'Official Fix',
                d: "A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available."
            },
            T: {
                l: 'Temporary Fix',
                d: "There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround."
            },
            W: {
                l: 'Workaround',
                d: "There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability."
            },
            U: {
                l: 'Unavailable',
                d: "There is either no solution available or it is impossible to apply."
            }
        },
        RC: {
            X: {
                l: 'Not Defined',
                d: "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning Confirmed."
            },
            U: {
                l: 'Unknown',
                d: "There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base score can be applied given the differences described. An example is a bug report which notes that an intermittent but non-reproducible crash occurs, with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result."
            },
            R: {
                l: 'Reasonable',
                d: "Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (Proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or 'left as an exercise to the reader') that gives assurances on how to reproduce the results."
            },
            C: {
                l: 'Confirmed',
                d: "Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability."
            }
        }
    };

    // Environmental Metrics
    envMetrics = {
        //...tempMetrics,
        CR: {
            X: {
                l: 'Not Defined',
                d: "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium."
            },
            L: {
                l: 'Low',
                d: "Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
            },
            M: {
                l: 'Medium',
                d: "Assigning this value to the metric will not influence the score."
            },
            H: {
                l: 'High',
                d: "Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
            }
        },
        IR: {
            X: {
                l: 'Not Defined',
                d: "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium."
            },
            L: {
                l: 'Low',
                d: "Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
            },
            M: {
                l: 'Medium',
                d: "Assigning this value to the metric will not influence the score."
            },
            H: {
                l: 'High',
                d: "Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
            }
        },
        AR: {
            X: {
                l: 'Not Defined',
                d: "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium."
            },
            L: {
                l: 'Low',
                d: "Loss of Availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
            },
            M: {
                l: 'Medium',
                d: "Assigning this value to the metric will not influence the score."
            },
            H: {
                l: 'High',
                d: "Loss of Availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
            }
        },
        MAV: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            N: {
                l: 'Network',
                d: "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed, up to and including the entire Internet. Such a vulnerability is often termed 'remotely exploitable' and can be thought of as an attack being exploitable at the protocol level one or more network hops away."
            },
            A: {
                l: 'Adjacent Network',
                d: "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN)."
            },
            L: {
                l: 'Local',
                d: "The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., tricking a legitimate user into opening a malicious document)."
            },
            P: {
                l: 'Physical',
                d: "The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent."
            }            
        },
        MAC: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            L: {
                l: 'Low',
                d: "Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component."
            },
            H: {
                l: 'High',
                d: "A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may require an attacker to: gather knowledge about the environment in which the vulnerable target/component exists; prepare the target environment to improve exploit reliability; or inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack)."
            }
        },
        MPR: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            N: {
                l: 'None',
                d: "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack."
            },
            L: {
                l: 'Low',
                d: "The attacker is authorized with (i.e., requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources."
            },
            H: {
                l: 'High',
                d: "The attacker is authorized with (i.e., requires) privileges that provide significant (e.g., administrative) control over the vulnerable component that could affect component-wide settings and files."
            }
        },
        MUI: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            N: {
                l: 'None',
                d: "The vulnerable system can be exploited without any interaction from any user."
            },
            R: {
                l: 'Required',
                d: "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited."
            }
        },
        MS: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            U: {
                l: 'Unchanged',
                d: "An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority."
            },
            C: {
                l: 'Changed',
                d: "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities."
            }
        },
        MC: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            N: {
                l: 'None',
                d: "There is no loss of confidentiality within the impacted component."
            },
            L: {
                l: 'Low',
                d: "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component."
            },
            H: {
                l: 'High',
                d: "There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact."
            }
        },
        MI: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            N: {
                l: 'None',
                d: "There is no loss of integrity within the impacted component."
            },
            L: {
                l: 'Low',
                d: "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component."
            },
            H: {
                l: 'High',
                d: "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component."
            }
        },
        MA: {
            X: {
                l: 'Not Defined',
                d: "The value assigned to the corresponding Base metric is used."
            },
            N: {
                l: 'None',
                d: "There is no impact to availability within the impacted component."
            },
            L: {
                l: 'Low',
                d: "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component."
            },
            H: {
                l: 'High',
                d: "There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
            }
        }
    };

    // Base Group Values
    bgv = {
        AV: 'NALP',
        AC: 'LH',
        PR: 'NLH',
        UI: 'NR',
        S: 'CU',
        C: 'HLN',
        I: 'HLN',
        A: 'HLN'
    };

    // Temporal Group Values
    tgv = {
        //...bgv,
        E: 'XUPFH',
        RL: 'XOTWU',
        RC: 'XURC'
    };

    // Environmental Group Values
    egv = { 
        //...tgv,
        CR: 'XLMH',
        IR: 'XLMH',
        AR: 'XLMH',
        MAV: 'XNALP',
        MAC: 'XLH',
        MPR: 'XNLH',
        MUI: 'XNR',
        MS: 'XUC',
        MC: 'XNLH',
        MI: 'XNLH',
        MA: 'XNLH'    
    };

    // All Group Values
    agv = {
        ...bgv,
        ...tgv,
        ...egv
    };

    // Severity Ratings
    severityRatings = [{
        name: "None",
        bottom: 0.0,
        top: 0.0
    }, {
        name: "Low",
        bottom: 0.1,
        top: 3.9
    }, {
        name: "Medium",
        bottom: 4.0,
        top: 6.9
    }, {
        name: "High",
        bottom: 7.0,
        top: 8.9
    }, {
        name: "Critical",
        bottom: 9.0,
        top: 10.0
    }];

    // Reference for all cvss board inputs
    this.metricInputs = {};
    
    // Find where to draw the cvss board
    this.rootElement = document.getElementById(id);

    // Create Form inside root element
    this.cvssform = createTag('form');
    this.cvssform.className = 'cvssjs';
    this.rootElement.appendChild(this.cvssform);

    // Create base metrics board
    this.createDOMTags(id, options, allGroup.base, baseMetrics);
    this.cvssform.appendChild(createTag('hr'));
    // Create CVSS String & Score
    this.locateScoreBox(this.cvssform, options);
    // Values to compose the vector
    this.vectorMetrics = { ...baseMetrics };

    if (showGroups > 1) {
        this.vectorMetrics = { ...this.vectorMetrics, ...tempMetrics, ...envMetrics };
        // Create temp metrics board
        this.createDOMTags(id, options, allGroup.temp, tempMetrics);
        this.cvssform.appendChild(createTag('hr'));
        // Create env metrics board
        this.createDOMTags(id, options, allGroup.env, envMetrics);
    }
}

function createTag(tag) {
    return document.createElement(tag);
};

/**
 * Create a description list for each of the metrics passed.
 * 
 * @param {ID for the DOM element from which to hung metrics elements} id 
 * @param {Options to customize events} options 
 * @param {Metrics to display} groups 
 */
CVSS.prototype.createDOMTags = function(id, options, groups, metrics) {
    for (group in groups) {
        // Create description list tag for each group of metrics
        const groupTag = createTag('dl');
        groupTag.setAttribute('class', group);
        this.cvssform.appendChild(groupTag);
        // Set a description term tag as header for the group metrics
        const groupHeader = createTag('dt');
        groupHeader.innerHTML = groups[group];
        groupTag.appendChild(groupHeader);
        // Create description for each metric
        for (metric in metrics[group]) {
            const metricTag = createTag('dd');
            groupTag.appendChild(metricTag);
            // Add a radio input to each metric
            const metricRadio = createTag('input');
            metricRadio.setAttribute('name', group);
            metricRadio.setAttribute('value', metric);
            metricRadio.setAttribute('id', id + group + metric);
            metricRadio.setAttribute('class', group + metric);
            metricRadio.setAttribute('type', 'radio');
            // Keep reference of metric input
            this.metricInputs[group + metric] = metricRadio;
            // Set onChange event for metric input
            const cvssInstance = this;
            metricRadio.onchange = function () {
                cvssInstance.setMetric(this);
            };
            // Append input to metric tag
            metricTag.appendChild(metricRadio);
            // Create long description tag for this metric
            const l = createTag('label');
            l.setAttribute('for', id + group + metric);
            l.appendChild(createTag('i')).setAttribute('class', group + metric);
            l.appendChild(document.createTextNode(metrics[group][metric].l + ' '));
            // Append the description
            metricTag.appendChild(l);
            // Finally, set metric title            
            metricTag.appendChild(createTag('small')).innerHTML = metrics[group][metric].d;
        }
    }
}

/**
 * Creates a box with the resulting cvss string and score
 * 
 * @param {reference to cvss form} f 
 * @param {options to customize events} options 
 */
CVSS.prototype.locateScoreBox = function(f, options) {
    this.vector = $("#cvssresults a.vector");

    // Add onSubmit event if passed as argument
    if (options.onsubmit) {
        f.appendChild(createTag('hr'));
        this.submitButton = f.appendChild(createTag('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
}

CVSS.prototype.set = function(vec) {
    let newVec = 'CVSS:3.1';
    
    for (const m in baseMetrics) newVec = this.formatVector(vec, m, newVec, agv, true);
    // Do not add temporal or environmental metrics if not present
    for (const m in tempMetrics) newVec = this.formatVector(vec, m, newVec, agv, false);
    for (const m in envMetrics) newVec = this.formatVector(vec, m, newVec, agv, false);

    this.update(newVec);
};

CVSS.prototype.formatVector = function(vec, m, newVec, values, addIfMissing) {
    let sep = '/';
    let match = (new RegExp('\\b(' + m + ':[' + values[m] + '])')).exec(vec);
    if (match !== null) {
        const check = match[0].replace(':', '');
        this.metricInputs[check].checked = true;
        newVec = newVec + sep + match[0];
    } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
        // compatibility with v2 only for CIA:C
        this.metricInputs[m + 'H'].checked = true;
        newVec = newVec + sep + m + ':H';
    } else {
        if (addIfMissing) {
            newVec = newVec + sep + m + ':_';
        }
        for (const j in this.vectorMetrics[m]) {
            // Metrics from the temp and/or env groups are not in the base vector
            if (this.metricInputs[m + j].checked) {
                newVec = newVec + sep + m + ":" + this.metricInputs[m + j].value;
            } else {
                this.metricInputs[m + j].checked = false;
            }
        }
    }
    return newVec
}

/**
 * Updates the results box.
 * 
 * @param {CVSS String} newVec 
 */
CVSS.prototype.update = function(newVec) {
    this.vector.text(newVec);
    var s31 = CVSS31.calculateCVSSFromMetrics(
        this.valueofradio(this.cvssform.elements["AV"]),
        this.valueofradio(this.cvssform.elements["AC"]), 
        this.valueofradio(this.cvssform.elements["PR"]),
        this.valueofradio(this.cvssform.elements["UI"]), 
        this.valueofradio(this.cvssform.elements["S"]), 
        this.valueofradio(this.cvssform.elements["C"]),
        this.valueofradio(this.cvssform.elements["I"]), 
        this.valueofradio(this.cvssform.elements["A"]),
        this.valueofradio(this.cvssform.elements["E"]), 
        this.valueofradio(this.cvssform.elements["RL"]), 
        this.valueofradio(this.cvssform.elements["RC"]),
        this.valueofradio(this.cvssform.elements["CR"]), 
        this.valueofradio(this.cvssform.elements["IR"]), 
        this.valueofradio(this.cvssform.elements["AR"]),
        this.valueofradio(this.cvssform.elements["MAV"]),
        this.valueofradio(this.cvssform.elements["MAC"]), 
        this.valueofradio(this.cvssform.elements["MPR"]),
        this.valueofradio(this.cvssform.elements["MUI"]), 
        this.valueofradio(this.cvssform.elements["MS"]), 
        this.valueofradio(this.cvssform.elements["MC"]),
        this.valueofradio(this.cvssform.elements["MI"]), 
        this.valueofradio(this.cvssform.elements["MA"]));
    
    $("#cvssresults .base-results span.score").text(s31.baseMetricScore);
    $("#cvssresults .temp-results span.score").text(s31.temporalMetricScore);
    $("#cvssresults .env-results span.score").text(s31.environmentalMetricScore);        

    if (s31.baseSeverity !== undefined && s31.baseSeverity !== null) {
        $("#cvssresults .base-results span.severity")
            .attr("class", s31.baseSeverity + " severity")
            .text(s31.baseSeverity);
    }
    if (s31.baseSeverity !== undefined && s31.baseSeverity !== null) {
        $("#cvssresults .temp-results span.severity")
            .attr("class", s31.temporalSeverity + " severity")
            .text(s31.temporalSeverity);
    }
    if (s31.baseSeverity !== undefined && s31.baseSeverity !== null) {        
        $("#cvssresults .env-results span.severity")
            .attr("class", s31.environmentalSeverity + " severity")
            .text(s31.environmentalSeverity);
    }

    $("#cvssresults .base-results a.vector").text(s31.vectorString);

    /*const rating = this.severityRating(s);
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    this.severity.title = rating.bottom + ' - ' + rating.top;*/
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};

/**
 * Replaces metric's value in the vector string
 * 
 * @param {New value for a metric} a 
 */
CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.text();
    if (/AV:.\/AC:.\/PR:.\/UI:.\/S:.\/C:.\/I:.\/A:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

/**
 * Checks which metric value is selected from a list of radio inputs.
 * 
 * @param {List of a metric's values radio inputs} e 
 */
CVSS.prototype.valueofradio = function(e) {
    for(var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CVSS.prototype.get = function() {
    return {
        score: $("#cvssresults .base-results span.score").text(),
        vector: this.vector.text()
    };
};