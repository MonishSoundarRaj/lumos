import streamlit as st
from PIL import Image
import numpy as np
import pandas as pd
import warnings
from streamlit_option_menu import option_menu
from matplotlib import pyplot as plt
import seaborn
from datetime import datetime
from collections import Counter, defaultdict
import json
import time 
import matplotlib

banner_image = Image.open('JOB TRACE VISULAZATION.png')

st.image(banner_image)

nav_bar_horizontal = option_menu(None, ["Job Run Time", "Job Arrival Pattern", "Model 3"], default_index=0, orientation="horizontal")

system_models_jrt = ["Blue Waters", "Mira", "Philly", "Helios"]

@st.cache_data
def load_data(file_path):
    return pd.read_csv(file_path)

bw_df = load_data("../data_blue_waters.csv")
mira_df_2 = load_data("../data_mira.csv")
hl_df = load_data("../data_helios.csv")
philly_df = load_data("../data_philly.csv")

columns=["job", "user", "project", "state", "gpu_num", "cpu_num", "node_num", "submit_time", "wait_time", "run_time", "wall_time", "node_hour"]

if nav_bar_horizontal == "Job Run Time":
    with st.form("select_chart_model_jrt"):
        #cdf
        st.write("### Select the chart you want to view")
        chart_select_radio_jrt = st.radio("Chart Selection", [None, "CDF Run Time Chart", "Detailed Run Time Distribution Chart"], horizontal=True)
        submit = st.form_submit_button("Select")
        if submit:
            st.write(f"You have selected: {chart_select_radio_jrt}")
            if chart_select_radio_jrt == "CDF Run Time Chart":
                st.markdown('<script>scrollToSection("cdf_chart_section")</script>', unsafe_allow_html=True)
            elif chart_select_radio_jrt == "Detailed Run Time Distribution Chart":
                st.markdown('<script>scrollToSection("drt_chart_section")</script>', unsafe_allow_html=True)

    if chart_select_radio_jrt == "CDF Run Time Chart":
        min_value_exp_run_time_slider = 0
        max_value_exp_run_time_slider = 8 

        with st.sidebar.form("CDF_chart_form_jrt"):
            st.write("## Adjust the following settings to change the CDF chart:")
            selected_system_models_jrt = []
            with st.expander("Select System Model(s)"):
                for item in system_models_jrt:
                    model_checkbox_jrt = st.checkbox(item)
                    if model_checkbox_jrt:
                        selected_system_models_jrt.append(item)

            cdf_frequency_slider_jrt = st.slider("Choose frequency range", min_value=0, max_value=100, step=20)
            cdf_run_time_slider_jrt = st.slider("Choose run time range (in powers of 10)", min_value_exp_run_time_slider, max_value_exp_run_time_slider, step=1)
            cdf_run_time_slider_value_jrt = int(10**cdf_run_time_slider_jrt)
                        
            submit_cdf_sidebar_button = st.form_submit_button("Apply")
            if submit_cdf_sidebar_button:
                if len(selected_system_models_jrt) > 1:
                    with st.spinner("Loading...."):
                        time.sleep(7)
                    st.success("Done!")
                else:
                    st.write("Please select the system models to see the graph")
            
        
        # Alex code here for displaying the cdf chart
        # Plots Figure 1(a) from page 3, 3.1.1
        st.markdown("<a name='cdf_chart_section'></a>", unsafe_allow_html=True)

        def plot_cdf(x, bins, xlabel, ylabel="Frequency (%)", color="", linestyle="--"):
            plt.xticks(fontsize=16)
            plt.yticks(fontsize=16)

            x = np.sort(x)
            cdf = 100 * np.arange(len(x)) / float(len(x))

            if color:
                plt.plot(x, cdf, linestyle=linestyle, linewidth=5, color=color)
            else:
                plt.plot(x, cdf, linestyle=linestyle, linewidth=5)

            plt.xlabel(xlabel, fontsize=20)
            plt.ylabel(ylabel, fontsize=20)
            plt.margins(0)
            plt.ylim(0, cdf_frequency_slider_jrt) 
            plt.xlim(10**0, cdf_run_time_slider_value_jrt) 

            plt.grid(True)

        plt.style.use("default")
        
        if len(selected_system_models_jrt) >= 1:
            st.write("CDF of Run Time Chart")
            for item in system_models_jrt:
                if "Blue Waters" in selected_system_models_jrt:
                    plot_cdf(bw_df["run_time"], 1000, "Time (s)", linestyle=":", color="blue")
                if "Mira" in selected_system_models_jrt:
                    plot_cdf(mira_df_2["run_time"], 1000, "Time (s)", linestyle="--", color="red")
                if "Philly" in selected_system_models_jrt:
                    plot_cdf(philly_df["run_time"], 1000, "Time (s)", linestyle="-.", color="green")
                if "Helios" in selected_system_models_jrt:
                    plot_cdf(hl_df["run_time"], 10009999, "Job Run Time (s)", linestyle="--", color="violet")
            
            plt.rc('legend', fontsize=12)
            plt.legend(selected_system_models_jrt, loc="lower right")
                    # Avoiding the user warning for now
            warnings.filterwarnings("ignore", message="Matplotlib is currently using agg, which is a non-GUI backend, so cannot show the figure.")
        
            plt.xscale("log")
            plt.show()
            st.pyplot(plt.gcf())
        else:
            st.write("## Please select one or more system models in the sidebar to plot the chart.")


    elif chart_select_radio_jrt == "Detailed Run Time Distribution Chart":
        # drt = detailed run time
        drt_time_ranges = ['0~30s', '30s~10min', '10min~1h', '1h~12h', "more than 12h"]

        with st.sidebar.form("detailed_run_time_form_jrt"):
            st.write("## Adjust the following settings to change the detailed run time chart:")
            drt_selected_system_models_jrt = []
            drt_selected_time_range_jrt = []
            with st.expander("Select System Model(s)"):
                for item in system_models_jrt:
                    drt_model_checkbox_jrt = st.checkbox(item)
                    if drt_model_checkbox_jrt:
                        drt_selected_system_models_jrt.append(item)
            drt_frequency_slider_jrt = st.slider("Choose frequency range", min_value=0.0, max_value=0.6, step=0.1)
            with st.expander("Select Run Time Range"):
                for item in drt_time_ranges:
                    drt_time_range_checkbox_jrt = st.checkbox(item)
                    if drt_time_range_checkbox_jrt:
                        drt_selected_time_range_jrt.append(item)

            submit_drt_sidebar_button = st.form_submit_button("Apply")

        # Alex code here for displaying the detailed run time chart
        # Plots Figure 1(b) from page 4, 3.1.2
        st.markdown("<a name='drt_chart_section'></a>", unsafe_allow_html=True)
        def lt_xs(data, t1, t2):
            lt10min_jobs_num = len(data[data < t2][data >= t1])
            all_jobs_num = len(data)
            return lt10min_jobs_num / all_jobs_num

        def lt_xs_all(t1, t2):
            res = []
            res.append(lt_xs(bw_df["run_time"], t1, t2))
            res.append(lt_xs(mira_df_2["run_time"], t1, t2))
            res.append(lt_xs(philly_df["run_time"], t1, t2))
            res.append(lt_xs(hl_df["run_time"], t1, t2))
            return res

        x = [0, 30, 600, 3600, 12 * 3600, 100000]
        x_value = np.array([1, 2, 3, 4, 5])
        labels = ['0~30s', '30s~10min', '10min~1h', '1h~12h', "more than 12h"]
        bw = []
        mr = []
        ply = []
        hl = []
        width = 0.2

        for i in range(1, len(x)):
            if labels[i-1] in drt_selected_time_range_jrt:
                res = lt_xs_all(x[i-1], x[i])
                bw.append(res[0])
                mr.append(res[1])
                ply.append(res[2])
                hl.append(res[3])

        x_value_selected = np.arange(1, len(drt_selected_time_range_jrt) + 1)

        if len(system_models_jrt) >= 1 and len(drt_selected_time_range_jrt) >= 1:
            for model in system_models_jrt:
                    if "Blue Waters" in drt_selected_system_models_jrt:
                        plt.bar(x_value_selected - 3 * width / 2, bw, width, edgecolor='black', hatch="x", color="blue")
                    if "Mira" in drt_selected_system_models_jrt:
                        plt.bar(x_value_selected - width / 2, mr, width, edgecolor='black', hatch="\\", color="red")
                    if "Philly" in drt_selected_system_models_jrt:
                        plt.bar(x_value_selected + width / 2, ply, width, edgecolor='black', hatch=".", color="green")
                    if "Helios" in drt_selected_system_models_jrt:
                        plt.bar(x_value_selected + 3 * width / 2, hl, width, edgecolor='black', hatch="-", color="violet")

            plt.xticks(x_value_selected, drt_selected_time_range_jrt)
            plt.legend(drt_selected_system_models_jrt, prop={'size': 12}, loc="upper right")
            plt.ylabel("Frequency (%)", fontsize=18)
            plt.xlabel("Job Run Time (s)", fontsize=18)
            st.set_option('deprecation.showPyplotGlobalUse', False)
            plt.show()
            st.pyplot()

        else:
            st.write("## Please select one or more system models and time ranges in the sidebar to plot the chart.")

# Job Arrival pattern page code
elif nav_bar_horizontal == "Job Arrival Pattern":
    system_models_jap = ["Blue Waters", "Mira", "Philly", "Helios"]
    selected_system_models_jap = system_models_jap.copy()
    chart_select_radio_jap = None;
    def get_time_of_day(time, timestamp=True):
            if timestamp:
                time = datetime.fromtimestamp(time)
            else:
                time = datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
            return (time.hour + (time.minute>30))%24, datetime.strftime(time, '%Y-%m-%d')

    def get_day_of_week(time):
            time = datetime.fromtimestamp(time)
            return time.isocalendar()[2], time.isocalendar()[1]
            
    def plot_time_submit(submit_time, xlabel, ylabel="Number of Submitted Jobs", week=False, marker="o", color=""):
            if week == True:
                time, days = list(zip(*[get_time_of_day(i) for i in submit_time]))
                dd = Counter()
                for i in time:
                    dd[i] += 1
                keys = sorted(dd.keys())
                n = len(set(days))
            else:
                days, weeks = list(zip(*[get_day_of_week(i) for i in submit_time]))
                dd = Counter()
                for i in days:
                    dd[i] += 1
                keys = sorted(dd.keys())
                n = len(set(weeks))
            plt.plot(keys, [np.array(dd[j])/n for j in keys], marker=marker, linewidth=3, markersize=12, color=color)

    with st.form("select_chart_model_jap"):
        st.write("#### Select a chart you want to view")
        chart_select_radio_jap = st.radio("Chart Selection", [None, "Daily Submit Pattern", "Weekly Submit Pattern", "Job Arrival Interval"], horizontal=True)
        submit_chart_radio_button_jap = st.form_submit_button("Select")
            
        if submit_chart_radio_button_jap:
            if chart_select_radio_jap is not None:
                  st.success(f"Done, You have selected: {chart_select_radio_jap}")
            else:
                text_color = "red"
                st.markdown(f'<span style="color:{text_color}">You have selected "None", please select an other option to view chart.</span>', unsafe_allow_html=True)

            if chart_select_radio_jap == "Daily Submit Pattern":
                st.markdown('<script>scrollToSection("dsp_chart_section")</script>', unsafe_allow_html=True)
            elif chart_select_radio_jap == "Weekly Submit Pattern":
                st.markdown('<script>scrollToSection("wsp_chart_section")</script>', unsafe_allow_html=True)
            elif chart_select_radio_jap == "Job Arrival Interval":
                st.markdown('<script>scrollToSection("jap_chart_section")</script>', unsafe_allow_html=True)
        

    # Models form  
    if chart_select_radio_jap is not None:
        st.sidebar.write("# Parameters Control Panel")
        with st.form("system_models_form_jap"):
            st.write("#### Select a model(s) below and click 'Set' to plot:")
            col1, col2, col3, col4 = st.columns(4)
            for idx, item in enumerate(system_models_jap):
                col = [col1, col2, col3, col4][idx % 4]
                model_checkbox_jap = col.checkbox(item, True)
                if not model_checkbox_jap:
                    selected_system_models_jap.remove(item)
                    print(selected_system_models_jap)
            submit_system_models_jap = st.form_submit_button("Set")
            if submit_system_models_jap:
                if (len(selected_system_models_jap) >= 1):
                    st.success(f"Done, you have set {selected_system_models_jap}")
                else:
                    text_color = "red"
                    st.markdown(f'<span style="color:{text_color}">Please select one or more system model(s) and then click "Set".</span>', unsafe_allow_html=True)
            
    #  Code for individual charts             
    if chart_select_radio_jap == "Daily Submit Pattern":
        if 'dsp_job_count_slider_jap' not in st.session_state:
           st.session_state['dsp_job_count_slider_jap'] = 180
        if 'dsp_hour_of_the_day_slider_jap' not in st.session_state:
            st.session_state['dsp_hour_of_the_day_slider_jap'] = 24
        
        with st.sidebar.form("dsp_personal_parameters_update_form"):
            st.write("## Adjust the following parameters and click on 'Apply Changes' to change the Daily Submit Pattern chart:")
            st.session_state['dsp_job_count_slider_jap'] = st.slider("Adjust Job Submit Count Range (y-axis):", min_value=0, max_value=180, step=20, value=st.session_state['dsp_job_count_slider_jap'])
            st.session_state['dsp_hour_of_the_day_slider_jap'] = st.slider("Adjust Hour of the Day Range (x-axis):", min_value=-1, max_value=24, step=1, value=st.session_state['dsp_hour_of_the_day_slider_jap'])
            dap_submit_parameters_button_jap = st.form_submit_button("Apply Changes")
            if dap_submit_parameters_button_jap:
                if len(selected_system_models_jap) >= 1:
                    st.write("running")
                else:
                     text_color = "red"
                     st.markdown(f'<span style = "color: {text_color}">Please set system model(s) above first and then adjust the parameters here.</span>', unsafe_allow_html=True)

        # Alex your code here  
        plt.figure(figsize=(12,5))
        plt.xticks(fontsize=16)
        plt.yticks(fontsize=16)

        for item in selected_system_models_jap:
            if "Blue Waters" in selected_system_models_jap:
                 plot_time_submit(bw_df["submit_time"], xlabel="Hour of the Day", week=True,marker="^", color="blue")
            if "Mira" in selected_system_models_jap:
                 plot_time_submit(mira_df_2["submit_time"], xlabel="Hour of the Day", week=True,marker="o", color="red")
            if "Philly" in selected_system_models_jap:
                plot_time_submit(philly_df["submit_time"], xlabel="Hour of the Day", week=True,marker="s", color="green")
            if "Helios" in selected_system_models_jap:
                plot_time_submit(hl_df["submit_time"], xlabel="Hour of the Day", week=True,marker="d", color="violet") 
 
        plt.xlabel("Hour of the Day", fontsize=20)
        plt.ylabel("Job Submit Count", fontsize=20)
        # plt.margins(1)
        st.set_option('deprecation.showPyplotGlobalUse', False)
        plt.ylim(0, st.session_state['dsp_job_count_slider_jap']) 
        plt.xlim(-1, st.session_state['dsp_hour_of_the_day_slider_jap'])
        # plt.ylim(bottom=0)
        # plt.xlim(-0.2, 23.2)
        plt.tight_layout()
        plt.grid(True)
        plt.legend(selected_system_models_jap,  prop={'size': 14}, loc="upper right")
        plt.rc('legend',fontsize=20)
        plt.show()
        st.pyplot()


    elif chart_select_radio_jap == "Weekly Submit Pattern":
         with st.sidebar.form("wsp_personal_parameters_update_form"):
            st.write("## Adjust the following parameters and click on 'Apply Changes' to change the Weekly Submit Pattern chart:")
            wsp_job_count_slider_jap = st.slider("Adjust Job Submit Count Range (x-axis):", min_value=0, max_value=3000, step=500)
            wsp_hour_of_the_day_slider_jap = st.slider("Adjust Day of the Week Range (y-axis):", min_value=0, max_value=8, step=1)
            wsp_submit_parameters_button_jap = st.form_submit_button("Apply Changes")
            if wsp_submit_parameters_button_jap:
                if len(selected_system_models_jap) >= 1:
                     with st.spinner("Loading...."):
                        time.sleep(2)
                     st.success(f"Done!")
                else:
                     text_color = "red"
                     st.markdown(f'<span style = "color: {text_color}">Please set system model(s) above first and then adjust the parameters here.</span>', unsafe_allow_html=True)

          # Alex your code here




    elif chart_select_radio_jap == "Job Arrival Interval":
        jap_min_value_exp_arrival_interval_slider = 0
        jap_max_value_exp_arrival_interval_slider = 8 

        with st.sidebar.form("jai_personal_parameters_update_form"):
            st.write("## Adjust the following parameters and click on 'Apply Changes' to change the Job Arrival Interval chart:")
            jai_job_count_slider_jap = st.slider("Adjust Frequency Range (x-axis):", min_value=0, max_value=100, step=20)
            jai_hour_of_the_day_slider_jap = st.slider("Adjust Job Arrival Interval Range (in powers of 10) (y-axis):", jap_min_value_exp_arrival_interval_slider, jap_max_value_exp_arrival_interval_slider, step=1)
            jai_hour_of_the_day_slider_value_jap = int(10**jai_hour_of_the_day_slider_jap)
            
            jai_submit_parameters_button_jap = st.form_submit_button("Apply Changes")
            if jai_submit_parameters_button_jap:
                if len(selected_system_models_jap) >= 1:
                     with st.spinner("Loading...."):
                        time.sleep(2)
                     st.success(f"Done!")
                else:
                    text_color = "red"
                    st.markdown(f'<span style = "color: {text_color}">Please set system model(s) above first and then adjust the parameters here.</span>', unsafe_allow_html=True)

        # Alex your code here


elif nav_bar_horizontal == "Model 3":
    # Code for "Model 3" section goes here
    st.write("This is the 'Model 3' section.")

else:
    st.write("Please select a section from the navigation bar.")

