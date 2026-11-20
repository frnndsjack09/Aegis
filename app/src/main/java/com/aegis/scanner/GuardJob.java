package com.aegis.scanner;

import android.app.job.JobParameters;
import android.app.job.JobService;

/** Periodic background job (about every 15 minutes) that runs the new-app check. */
public class GuardJob extends JobService {

    @Override
    public boolean onStartJob(JobParameters params) {
        new Thread(() -> {
            try {
                Guard.checkChanged(getApplicationContext());
                Guard.weeklyScan(getApplicationContext());
            } finally {
                jobFinished(params, false);
            }
        }, "aegis-guard").start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true; // try again at the next run
    }
}
